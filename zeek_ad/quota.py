"""API 한도 초과(HTTP 429)를 한 번 만나면 그 실행의 남은 호출을 막는 차단기(circuit breaker).

왜 따로 두는가(2026-11-23 실습망 기록, 단계 6 진행 기록 스물여섯째 작업):
요금 상한에 걸린 뒤에도 사건마다 임베딩 6번 + 보고서 2번 + 판단 모델 10번을 부르고 그 사이를 기다려, 에이전트 한 번
실행이 4시간 가까이 걸렸고 그동안 수신 파일이 쌓였다. 한도 초과는 몇 초 뒤에 다시 불러도 풀리지 않는다.
한 번 보면 그 실행에서는 더 부르지 않고, 다음 실행(감시 프로그램의 다음 주기)에서 다시 해 본다.

llm_report.py·send_decision.py·rag.py는 평가 동결 파일(configs/agent/freeze.v1.json)이라 고치지 않는다.
그 함수들이 쓰는 클라이언트를 감싸서(GuardedClient) 밖에서 429를 알아낸다.
- Breaker: 열림/닫힘 표시. 처음에는 닫혀 있고(호출 허용), 429를 보면 열린다(호출 차단). 실행(프로세스) 하나 동안만 산다.
- GuardedClient: client.models.*, client.decisions.* 호출을 그대로 넘기되, 429면 차단기를 열고 예외는 그대로 던진다.
  차단기가 열린 뒤의 호출은 네트워크 없이 바로 QuotaExhausted를 던진다.
- retrieve_once: 운영 검색. 질의 임베딩을 한 번만 시도하고 실패하면 바로 BM25로 찾는다
  (rag.gemini_embed의 기본 재시도 6번은 문서 수천 개를 처음 임베딩할 때의 분당 한도 대응이다).
"""


class QuotaExhausted(RuntimeError):
    """한도 초과로 호출하지 않았거나, 한도 초과 때문에 이 사건을 끝까지 처리하지 못했다."""


class Breaker:
    """차단기. open이 True면 호출을 막는다. where는 처음 429를 본 호출 이름이다."""

    def __init__(self):
        self.open = False
        self.where = None

    def trip(self, where):
        if not self.open:
            self.open, self.where = True, where


def status_code(error):
    """예외에서 HTTP 상태 코드를 꺼낸다. google-genai는 호출 종류에 따라 code 또는 status_code에 둔다. 없으면 None."""
    for name in ("code", "status_code"):
        value = getattr(error, name, None)
        if isinstance(value, int):
            return value
    return None


class _GuardedResource:
    """client.models 같은 하위 객체 하나를 감싼다. 실제 객체는 처음 부를 때 꺼낸다."""

    def __init__(self, client, name, breaker):
        self._client, self._name, self._breaker = client, name, breaker

    def __getattr__(self, method):
        def call(*args, **kwargs):
            where = f"{self._name}.{method}"
            if self._breaker.open:
                raise QuotaExhausted(f"한도 초과로 호출하지 않음: {where}")
            try:
                return getattr(getattr(self._client, self._name), method)(*args, **kwargs)
            except Exception as e:
                if status_code(e) == 429:
                    self._breaker.trip(where)
                raise

        return call


class GuardedClient:
    """genai.Client 대신 넘기는 감싼 클라이언트. call_llm·call_decision이 쓰는 models·decisions만 있다."""

    def __init__(self, client, breaker):
        self.models = _GuardedResource(client, "models", breaker)
        self.decisions = _GuardedResource(client, "decisions", breaker)


def blocked_call(model):
    """차단기가 이미 열려 LLM을 부르지 않았을 때의 호출 기록(llm_report.call_llm의 반환과 같은 모양)."""
    return {"model": model, "model_version": None, "seconds": 0.0, "usage": None, "attempts": 0,
            "error": "call: QuotaExhausted", "report": None}


def retrieve_once(conn, query, config, api_key, breaker, embed=None):
    """운영 검색 1건: Gemini 질의 임베딩(1번만 시도) → pgvector 상위 k. 실패하면 BM25(rag.retrieve의 대체 경로).

    반환은 rag.retrieve와 같다: ([[{"attack_id", "name", "tactics"}]], 실제로 쓴 방법, 실패 이유 또는 None).
    embed: 시험에서 임베딩 함수를 바꿔 넣는 자리(기본은 Gemini).
    """
    from zeek_ad.rag import gemini_embed, retrieve

    reason = "QuotaExhausted" if breaker.open else None
    if api_key and not breaker.open:
        try:
            if embed is None:
                from google import genai
                client = genai.Client(api_key=api_key)

                def embed(texts):
                    return gemini_embed(client, texts, config["query_task_type"], retries=1, log=lambda *_: None)
            vector = embed([query])[0]
            from pgvector.psycopg import register_vector
            register_vector(conn)
            rows = conn.execute(
                """SELECT e.attack_id, d.name, d.tactics
                   FROM rag.document_embedding e JOIN rag.attack_document d USING (attack_id)
                   WHERE e.model_id = %s ORDER BY e.embedding <=> %s, e.attack_id LIMIT %s""",
                (config["model_id"], vector, config["top_k"])).fetchall()
            return [[{"attack_id": r[0], "name": r[1], "tactics": list(r[2])} for r in rows]], config["method"], None
        except Exception as e:  # noqa: BLE001 (검색 실패가 보고서 흐름을 막지 않게 한다)
            if status_code(e) == 429:
                breaker.trip("models.embed_content")
            reason = type(e).__name__
    found, method, fallback_reason = retrieve(conn, [query], config, None)   # 키 없이 부르면 BM25로 찾는다
    return found, method, reason or fallback_reason
