"""ATT&CK 문서 검색 공통 도구(단계 5a). 검색 방법(BM25·임베딩·혼합)을 같은 질의 세트와 지표로 비교한다.

- embedding_text: 문서에서 검색에 쓸 글만 남긴다. 머리(이름·분류·전술·플랫폼), 설명, 탐지 절만 쓰고
  완화책(Mitigations)과 사용 그룹(Used By)은 뺀다. 둘 다 "행동"이 아니라 대응책·행위자 목록이라
  네트워크 행동 질의와 엉뚱하게 겹칠 수 있다.
- evaluate: 질의마다 기대 기법 중 하나라도 상위 k에 있으면 적중(hit@k), 첫 정답 순위의 역수 평균(MRR).
"""

import hashlib
import json
import re
import time

import numpy as np

KEPT_SECTIONS = ("## Description", "## Detection")
HIT_KS = (1, 3, 5)

# 임베딩 모델 설정. model_id는 DB의 document_embedding.model_id와 결과 파일에 그대로 남는다.
GEMINI_MODEL = "gemini-embedding-001"
GEMINI_DIMS = 768
GEMINI_MODEL_ID = f"{GEMINI_MODEL}@{GEMINI_DIMS}"
GEMINI_BATCH = 100              # 요청 하나에 넣는 글 수 상한
GEMINI_FREE_TPM = 30_000        # 무료 등급 분당 임베딩 토큰 한도
GEMINI_CHARS_PER_TOKEN = 3.5    # 토큰 추정용. 실측(가장 긴 글 8,039자 = 1,692토큰, 4.75자)보다 작게 잡아 넉넉하게

# 로컬 임베딩(bge). 한 번에 512토큰까지만 읽는다(문서 706개 중 507개가 넘음, 2026-11-14 실측) → 조각으로 나눈다.
BGE_MODEL = "BAAI/bge-base-en-v1.5"
BGE_REVISION = "a5beb1e3e68b9ab74eb54cfd186867f64f240e1a"  # Hugging Face commit 고정
BGE_MODEL_ID = "bge-base-en-v1.5@768+chunk512-max"
BGE_MAX_TOKENS = 510            # 512 - 특수 토큰 2개([CLS], [SEP])
BGE_QUERY_PREFIX = "Represent this sentence for searching relevant passages: "  # 모델 카드 권장(짧은 질의 → 긴 문서)

RRF_K = 60                      # RRF 표준 값(Cormack 외 2009). 결과를 보고 바꾸지 않는다


def embedding_text(document):
    """문서 본문에서 머리·설명·탐지 절만 남긴다. 절 순서는 머리 → 설명 → 완화책 → 탐지 → 사용 그룹이다."""
    parts = re.split(r"(?m)^(?=## )", document)
    head, sections = parts[0], parts[1:]
    kept = [s for s in sections if s.startswith(KEPT_SECTIONS)]
    if len(kept) != len(KEPT_SECTIONS):
        raise ValueError("설명 또는 탐지 절이 없다")
    return (head + "".join(kept)).strip()


def load_corpus(conn):
    """DB의 기법 문서를 (attack_id 목록, 검색용 글 목록)으로 읽는다. 순서는 attack_id 순."""
    rows = conn.execute("SELECT attack_id, document FROM rag.attack_document ORDER BY attack_id").fetchall()
    return [r[0] for r in rows], [embedding_text(r[1]) for r in rows]


def text_sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tokenize(text):
    """BM25용 단어 나누기: 소문자 영숫자 덩어리. 어간 추출은 하지 않는다(login과 logins는 다른 단어)."""
    return re.findall(r"[a-z0-9]+", text.lower())


def l2_normalize(vectors):
    """길이를 1로 맞춘다. 768차원은 3072차원을 잘라 쓴 것이라 길이가 1이 아니다(공식 문서: 다시 정규화)."""
    v = np.asarray(vectors, dtype=np.float32)
    return v / np.linalg.norm(v, axis=1, keepdims=True)


def token_batches(texts, budget):
    """글을 순서대로 묶되, 한 묶음의 추정 토큰이 budget을 넘지 않게 한다. (시작 위치, 끝 위치, 추정 토큰)."""
    batches, start, used = [], 0, 0
    for i, t in enumerate(texts):
        est = len(t) / GEMINI_CHARS_PER_TOKEN
        if i > start and (used + est > budget or i - start >= GEMINI_BATCH):
            batches.append((start, i, used))
            start, used = i, 0
        used += est
    batches.append((start, len(texts), used))
    return batches


def gemini_embed(client, texts, task_type, tokens_per_min=GEMINI_FREE_TPM, retries=6, log=print):
    """Gemini 임베딩. task_type: 문서는 RETRIEVAL_DOCUMENT, 질의는 RETRIEVAL_QUERY.

    무료 등급 한도는 분당 3만 토큰이다(2026-11-14 실측 오류 메시지). 묶음을 한도의 2/3 이하로 만들고,
    보낸 토큰만큼 기다려 분당 한도를 넘지 않게 한다. 그래도 429가 나면 기다렸다 다시 보낸다.
    결과는 정규화한 (n, 768) 배열이다.
    """
    from google.genai import types, errors  # 임베딩을 쓸 때만 필요하다

    config = types.EmbedContentConfig(task_type=task_type, output_dimensionality=GEMINI_DIMS)
    batches = token_batches(texts, tokens_per_min * 2 / 3)
    out = []
    for n, (start, end, est) in enumerate(batches, 1):
        for attempt in range(retries):
            try:
                resp = client.models.embed_content(model=GEMINI_MODEL, contents=texts[start:end], config=config)
                break
            except errors.APIError as e:
                if e.code != 429 or attempt == retries - 1:
                    raise
                time.sleep(30 * (attempt + 1))
        if len(resp.embeddings) != end - start:
            raise RuntimeError(f"임베딩 수가 다르다: {len(resp.embeddings)} != {end - start}")
        out.extend(e.values for e in resp.embeddings)
        log(f"  묶음 {n}/{len(batches)}: {end - start}개, 추정 {est:,.0f}토큰")
        if n < len(batches):
            time.sleep(60 * est / tokens_per_min)
    return l2_normalize(out)


def split_head(text):
    """검색용 글을 (머리, 본문)으로 나눈다. 머리는 '# [Txxxx] 이름'과 분류·전술·플랫폼 줄이다."""
    i = text.index("## Description")
    return text[:i].strip(), text[i:]


def chunk_for_model(text, n_tokens, max_tokens=BGE_MAX_TOKENS):
    """토큰 한도가 짧은 모델(bge 512)용 조각 나누기. 조각마다 머리를 붙이고 본문 줄을 한도까지 채운다.

    n_tokens: 글 → 토큰 수 함수(특수 토큰 제외). 한 줄이 한도보다 길면 그 줄만으로 조각을 만든다(모델이 뒤를 자른다).
    """
    head, body = split_head(text)
    budget = max_tokens - n_tokens(head) - 1
    chunks, cur, used = [], [], 0
    for line in body.splitlines():
        if not line.strip():
            continue
        t = n_tokens(line) + 1
        if cur and used + t > budget:
            chunks.append(head + "\n" + "\n".join(cur))
            cur, used = [], 0
        cur.append(line)
        used += t
    if cur:
        chunks.append(head + "\n" + "\n".join(cur))
    return chunks


def bge_rank(ids, texts, query_texts, device="cuda"):
    """bge로 문서 조각과 질의를 임베딩하고, 문서 점수 = 질의와 가장 가까운 조각의 코사인 유사도(max)로 줄 세운다.

    돌려주는 것: (질의별 전체 순위 목록, 질의 벡터, 조각 통계).
    """
    from sentence_transformers import SentenceTransformer  # bge를 쓸 때만 필요하다

    model = SentenceTransformer(BGE_MODEL, revision=BGE_REVISION, device=device)
    tok = model.tokenizer
    n_tokens = lambda s: len(tok(s, add_special_tokens=False)["input_ids"])  # noqa: E731
    chunks, owner = [], []
    for i, t in enumerate(texts):
        for c in chunk_for_model(t, n_tokens):
            chunks.append(c)
            owner.append(i)
    owner = np.asarray(owner)
    doc_vecs = model.encode(chunks, batch_size=64, normalize_embeddings=True, convert_to_numpy=True)
    q_vecs = model.encode([BGE_QUERY_PREFIX + q for q in query_texts], normalize_embeddings=True,
                          convert_to_numpy=True)
    over = sum(1 for c in chunks if n_tokens(c) > BGE_MAX_TOKENS)  # 한 줄이 한도보다 길어 잘리는 조각
    rankings = []
    for qv in q_vecs:
        sims = doc_vecs @ qv
        best = np.full(len(ids), -np.inf)
        np.maximum.at(best, owner, sims)
        rankings.append(sorted(range(len(ids)), key=lambda i: (-best[i], ids[i])))
    stats = {"chunks": len(chunks), "chunks_per_doc_max": int(np.bincount(owner).max()),
             "chunks_truncated": over}
    return [[ids[i] for i in r] for r in rankings], q_vecs, stats


def rrf(rankings, k=RRF_K):
    """Reciprocal Rank Fusion: 문서 점수 = Σ 1/(k + 방법별 순위). 점수 척도를 맞추지 않고 순위만 쓴다.

    rankings: 방법별 전체 순위 목록(같은 문서 집합). 같은 점수는 attack_id 순.
    """
    score = {}
    for ranked in rankings:
        for r, doc in enumerate(ranked, 1):
            score[doc] = score.get(doc, 0.0) + 1.0 / (k + r)
    return sorted(score, key=lambda d: (-score[d], d))


def retrieve(conn, query_texts, config, api_key=None):
    """운영 검색(configs/rag/retrieval.v1.json): Gemini 질의 임베딩 → pgvector 상위 k.

    질의 임베딩이 실패하면(키 없음·한도·네트워크) BM25로 대신 찾고 method에 그 사실을 남긴다.
    반환: (질의별 [{"attack_id", "name", "tactics"}], 실제로 쓴 방법, 실패 이유 또는 None).
    """
    from pgvector.psycopg import register_vector

    k = config["top_k"]
    meta = {r[0]: {"attack_id": r[0], "name": r[1], "tactics": list(r[2])} for r in conn.execute(
        "SELECT attack_id, name, tactics FROM rag.attack_document").fetchall()}
    try:
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY 없음")
        from google import genai
        vecs = gemini_embed(genai.Client(api_key=api_key), list(query_texts), config["query_task_type"],
                            log=lambda *_: None)
        register_vector(conn)
        out = [[meta[r[0]] for r in conn.execute(
            """SELECT attack_id FROM rag.document_embedding WHERE model_id = %s
               ORDER BY embedding <=> %s, attack_id LIMIT %s""", (config["model_id"], v, k)).fetchall()]
            for v in vecs]
        return out, config["method"], None
    except Exception as e:  # noqa: BLE001 — 검색 실패가 보고서 흐름을 막지 않게 한다
        from rank_bm25 import BM25Okapi
        ids, texts = load_corpus(conn)
        bm25 = BM25Okapi([tokenize(t) for t in texts])
        out = []
        for q in query_texts:
            s = bm25.get_scores(tokenize(q))
            out.append([meta[ids[i]] for i in sorted(range(len(ids)), key=lambda i: (-s[i], ids[i]))[:k]])
        return out, config["fallback"], f"{type(e).__name__}"


def load_query_set(path):
    """고정(frozen)된 질의 세트만 읽는다. 고정 전 질의로 결과를 보면 질의를 결과에 맞추게 된다."""
    qs = json.loads(path.read_text(encoding="utf-8"))
    if qs["status"] != "frozen":
        raise ValueError(f"질의 세트가 고정되지 않았다: {qs['status']}")
    return qs


def evaluate(queries, rankings, depth=20):
    """rankings: {질의 id: 순위대로 나열한 attack_id 목록}. 질의별 첫 정답 순위와 전체 hit@k·MRR을 돌려준다.

    depth보다 뒤에 있으면 못 찾은 것으로 본다(MRR 0).
    """
    per_query, rr = [], []
    for q in queries:
        ranked = rankings[q["id"]][:depth]
        first = next((i + 1 for i, a in enumerate(ranked) if a in q["expected"]), None)
        rr.append(1.0 / first if first else 0.0)
        per_query.append({"id": q["id"], "first_hit_rank": first, "top5": ranked[:5]})
    n = len(queries)
    summary = {f"hit@{k}": sum(1 for p in per_query if p["first_hit_rank"] and p["first_hit_rank"] <= k) / n
               for k in HIT_KS}
    summary["mrr"] = sum(rr) / n
    summary["queries"] = n
    return summary, per_query
