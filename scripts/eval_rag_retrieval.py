"""ATT&CK 문서 검색 방법을 고정 질의 세트로 비교한다(단계 5a-3~5).

방법
- bm25: 단어 겹침(rank-bm25 Okapi).
- gemini: gemini-embedding-001 768차원. 문서 벡터는 DB(rag.document_embedding), 거리는 pgvector가 계산(<=>).
- bge: bge-base-en-v1.5 로컬. 512토큰 조각으로 나눠 임베딩, 문서 점수 = 가장 가까운 조각(max). 평가 때 바로 계산.
- rrf-bm25-gemini, rrf-bm25-bge: 두 방법의 전체 순위를 RRF(k=60)로 합친다.

선택 규칙(질의 세트 고정 전에 정함): hit@5 → MRR → 로컬(외부 API 없음) 우선.
결과: outputs/rag/eval/<시각>-compare/metrics.json, 임베딩 질의 벡터(<방법>_query_vectors.npy).
예: python scripts/eval_rag_retrieval.py --methods bm25 gemini bge rrf-bm25-gemini rrf-bm25-bge
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import numpy as np
from pgvector.psycopg import register_vector
from rank_bm25 import BM25Okapi

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect, load_env  # noqa: E402
from zeek_ad.provenance import file_record  # noqa: E402
from zeek_ad.rag import (BGE_MODEL_ID, GEMINI_MODEL_ID, RRF_K, bge_rank, evaluate, gemini_embed,  # noqa: E402
                         load_corpus, load_query_set, rrf, text_sha256, tokenize)

QUERY_SET = PROJECT_ROOT / "configs" / "rag" / "query-set.v1.json"
OUT_ROOT = PROJECT_ROOT / "outputs" / "rag" / "eval"
DEPTH = 20          # 평가는 상위 20까지 본다(그 뒤는 못 찾음)
METHODS = ["bm25", "gemini", "bge", "rrf-bm25-gemini", "rrf-bm25-bge"]
LOCAL = {"bm25", "bge", "rrf-bm25-bge"}  # 외부 API 없이 도는 방법
MODEL_IDS = {"gemini": GEMINI_MODEL_ID, "bge": BGE_MODEL_ID}


def rank_bm25(ids, texts, queries):
    """BM25(Okapi, 기본 k1=1.5·b=0.75). 전체 순위. 같은 점수는 attack_id 순서(안정 정렬)."""
    bm25 = BM25Okapi([tokenize(t) for t in texts])
    out = []
    for q in queries:
        scores = bm25.get_scores(tokenize(q["text"]))
        out.append([ids[i] for i in sorted(range(len(ids)), key=lambda i: -scores[i])])
    return out


def rank_gemini(ids, texts, queries):
    """DB의 Gemini 문서 임베딩과 질의 벡터의 코사인 거리로 전체 순위. 문서 임베딩이 지금 글과 다르면 멈춘다."""
    from google import genai
    client = genai.Client(api_key=load_env()["GEMINI_API_KEY"])
    q_vecs = gemini_embed(client, [q["text"] for q in queries], "RETRIEVAL_QUERY", log=lambda *_: None)
    expected = {i: text_sha256(t) for i, t in zip(ids, texts)}
    with connect("zeekad_api") as conn:
        register_vector(conn)
        stored = dict(conn.execute("SELECT attack_id, text_sha256 FROM rag.document_embedding WHERE model_id = %s",
                                   (GEMINI_MODEL_ID,)).fetchall())
        if stored != expected:
            sys.exit(f"Gemini 문서 임베딩이 지금 글과 맞지 않는다(저장 {len(stored)}개). embed_attack_docs.py를 먼저 돌린다")
        out = [[r[0] for r in conn.execute(
            """SELECT attack_id FROM rag.document_embedding WHERE model_id = %s
               ORDER BY embedding <=> %s, attack_id""", (GEMINI_MODEL_ID, v)).fetchall()] for v in q_vecs]
    return out, q_vecs


def select(summaries):
    """선택 규칙: hit@5가 높은 것 → MRR이 높은 것 → 로컬 우선."""
    return max(summaries, key=lambda m: (summaries[m]["hit@5"], round(summaries[m]["mrr"], 6), m in LOCAL))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--methods", nargs="+", choices=METHODS, default=METHODS)
    args = parser.parse_args()

    qs = load_query_set(QUERY_SET)
    queries = qs["queries"]
    with connect("zeekad_api") as conn:
        ids, texts = load_corpus(conn)
    missing = sorted({e for q in queries for e in q["expected"]} - set(ids))
    if missing:
        sys.exit(f"기대 기법이 문서에 없다: {missing}")

    needed = set(args.methods) | {p for m in args.methods if m.startswith("rrf-") for p in m.split("-")[1:]}
    full, q_vecs, extra = {}, {}, {}
    if "bm25" in needed:
        full["bm25"] = rank_bm25(ids, texts, queries)
    if "gemini" in needed:
        full["gemini"], q_vecs["gemini"] = rank_gemini(ids, texts, queries)
    if "bge" in needed:
        full["bge"], q_vecs["bge"], extra["bge"] = bge_rank(ids, texts, [q["text"] for q in queries])
    for m in args.methods:
        if m.startswith("rrf-"):
            a, b = m.split("-")[1:]
            full[m] = [rrf([ra, rb]) for ra, rb in zip(full[a], full[b])]

    results = {}
    for m in args.methods:
        summary, per_query = evaluate(queries, {q["id"]: r for q, r in zip(queries, full[m])}, depth=DEPTH)
        results[m] = {"summary": summary, "per_query": per_query, "local": m in LOCAL, **extra.get(m, {})}
    summaries = {m: r["summary"] for m, r in results.items()}
    chosen = select(summaries)

    corpus_sha = hashlib.sha256("\n".join(f"{i}\t{t}" for i, t in zip(ids, texts)).encode("utf-8")).hexdigest()
    run = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-compare"
    out = OUT_ROOT / run
    out.mkdir(parents=True)
    for m, v in q_vecs.items():  # 같은 질의 벡터로 다시 평가할 수 있게 남긴다
        np.save(out / f"{m}_query_vectors.npy", v)
    result = {"query_set": {**file_record(QUERY_SET), "config_id": qs["config_id"]},
              "corpus": {"documents": len(ids), "embedding_text_sha256": corpus_sha},
              "depth": DEPTH, "rrf_k": RRF_K, "model_ids": MODEL_IDS,
              "selection_rule": "hit@5 → MRR → 로컬 우선", "selected": chosen, "methods": results}
    (out / "metrics.json").write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    print("질의별 첫 정답 순위(- = 20위 밖)")
    print("      " + "".join(f"{m:>17}" for m in args.methods))
    for k, q in enumerate(queries):
        print(f"{q['id']:<6}" + "".join(f"{str(results[m]['per_query'][k]['first_hit_rank'] or '-'):>17}"
                                       for m in args.methods))
    print()
    for m in args.methods:
        s = summaries[m]
        print(f"{m:<17} hit@1 {s['hit@1']:.3f}  hit@3 {s['hit@3']:.3f}  hit@5 {s['hit@5']:.3f}  MRR {s['mrr']:.3f}"
              f"{'  (로컬)' if m in LOCAL else ''}")
    if "bge" in extra:
        print(f"bge 조각: {extra['bge']}")
    print(f"선택: {chosen}")
    print(f"결과: outputs/rag/eval/{run}/metrics.json")


if __name__ == "__main__":
    main()
