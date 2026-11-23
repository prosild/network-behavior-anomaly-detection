"""한도 초과 차단기(zeek_ad.quota) 시험. 네트워크·DB 없이 가짜 클라이언트로 본다.

zeek-ad 환경에서 실행한다: python -m unittest tests.test_quota -v
확인하는 것:
- 429를 보면 차단기가 열리고, 그 뒤 호출은 실제 클라이언트에 가지 않고 QuotaExhausted가 난다.
- 429가 아닌 오류(시간 초과, 500)는 차단기를 열지 않는다.
- call_llm·call_decision(동결 파일)에 감싼 클라이언트를 넘기면 429 한 번 뒤로는 실제 호출이 없다.
- 운영 검색(retrieve_once)은 임베딩을 한 번만 시도하고, 실패하거나 차단기가 열려 있으면 BM25로 찾는다.
"""

import unittest
from unittest import mock

from zeek_ad.llm_report import call_llm
from zeek_ad.quota import Breaker, GuardedClient, QuotaExhausted, blocked_call, retrieve_once, status_code
from zeek_ad.send_decision import call_decision


class ApiError(Exception):
    """google.genai.errors.APIError처럼 code에 HTTP 상태를 둔다."""

    def __init__(self, code):
        super().__init__(f"HTTP {code}")
        self.code = code


class StatusError(Exception):
    """판단 모델 쪽 오류처럼 status_code에 HTTP 상태를 둔다."""

    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status_code = status


def failing_client(error):
    client = mock.Mock()
    client.models.generate_content.side_effect = error
    client.decisions.create.side_effect = error
    return client


class BreakerTest(unittest.TestCase):
    def test_status_code_reads_both_attributes(self):
        self.assertEqual(status_code(ApiError(429)), 429)
        self.assertEqual(status_code(StatusError(429)), 429)
        self.assertIsNone(status_code(TimeoutError()))

    def test_429_opens_and_blocks_later_calls(self):
        breaker, client = Breaker(), failing_client(ApiError(429))
        guarded = GuardedClient(client, breaker)
        with self.assertRaises(ApiError):
            guarded.models.generate_content(model="m")
        self.assertTrue(breaker.open)
        self.assertEqual(breaker.where, "models.generate_content")
        with self.assertRaises(QuotaExhausted):
            guarded.decisions.create(model="d")              # 다른 호출도 막힌다
        client.decisions.create.assert_not_called()
        self.assertEqual(client.models.generate_content.call_count, 1)

    def test_other_errors_do_not_open(self):
        for error in (ApiError(500), ApiError(400), TimeoutError()):
            breaker = Breaker()
            with self.assertRaises(type(error)):
                GuardedClient(failing_client(error), breaker).models.generate_content(model="m")
            self.assertFalse(breaker.open)

    def test_success_passes_through(self):
        client = mock.Mock()
        client.models.generate_content.return_value = "ok"
        self.assertEqual(GuardedClient(client, Breaker()).models.generate_content(model="m"), "ok")


class FrozenCallersTest(unittest.TestCase):
    """동결 파일의 재시도 반복이 감싼 클라이언트와 만나면 실제 호출은 한 번뿐이다."""

    @mock.patch("time.sleep")
    def test_call_llm_hits_api_once(self, _sleep):
        breaker, client = Breaker(), failing_client(ApiError(429))
        record = call_llm(GuardedClient(client, breaker), {"model": "m", "retries": 1, "temperature": 0}, "sys", {})
        self.assertEqual(client.models.generate_content.call_count, 1)
        self.assertEqual(record["error"], "call: QuotaExhausted")   # 두 번째 시도는 차단기가 막았다
        self.assertIsNone(record["report"])
        self.assertTrue(breaker.open)

    @mock.patch("time.sleep")
    def test_call_decision_hits_api_once(self, _sleep):
        breaker, client = Breaker(), failing_client(StatusError(429))
        config = {"model": "d", "retries": 1, "question_id": "slack", "criteria": {"send": "s"}, "instructions": "i"}
        record = call_decision(GuardedClient(client, breaker), config, {})
        self.assertEqual(client.decisions.create.call_count, 1)
        self.assertIsNone(record["choice"])
        self.assertTrue(breaker.open)

    def test_blocked_call_looks_like_a_failed_call(self):
        record = blocked_call("m")
        self.assertEqual((record["attempts"], record["report"], record["error"]), (0, None, "call: QuotaExhausted"))


class FakeConn:
    def execute(self, sql, params=()):
        result = mock.Mock()
        result.fetchall.return_value = [("T1046", "Network Service Discovery", ["discovery"])]
        return result


CONFIG = {"query_task_type": "RETRIEVAL_QUERY", "model_id": "gemini-embedding-001", "top_k": 8,
          "method": "gemini", "fallback": "bm25"}
BM25 = ([[{"attack_id": "T1595", "name": "Active Scanning", "tactics": []}]], "bm25", "RuntimeError")


@mock.patch("pgvector.psycopg.register_vector")
@mock.patch("zeek_ad.rag.retrieve", return_value=BM25)
class RetrieveOnceTest(unittest.TestCase):
    def test_embedding_success_uses_vector_search(self, bm25, _reg):
        found, method, reason = retrieve_once(FakeConn(), "q", CONFIG, "key", Breaker(), embed=lambda t: [[0.1]])
        self.assertEqual((found[0][0]["attack_id"], method, reason), ("T1046", "gemini", None))
        bm25.assert_not_called()

    def test_429_opens_breaker_and_falls_back(self, bm25, _reg):
        breaker, embed = Breaker(), mock.Mock(side_effect=ApiError(429))
        found, method, reason = retrieve_once(FakeConn(), "q", CONFIG, "key", breaker, embed=embed)
        self.assertEqual((found[0][0]["attack_id"], method, reason), ("T1595", "bm25", "ApiError"))
        self.assertTrue(breaker.open)
        # 다음 사건: 임베딩을 부르지 않고 바로 BM25
        _, method, reason = retrieve_once(FakeConn(), "q2", CONFIG, "key", breaker, embed=embed)
        self.assertEqual((method, reason), ("bm25", "QuotaExhausted"))
        self.assertEqual(embed.call_count, 1)

    def test_other_error_falls_back_without_opening(self, bm25, _reg):
        breaker = Breaker()
        _, method, reason = retrieve_once(FakeConn(), "q", CONFIG, "key", breaker,
                                          embed=mock.Mock(side_effect=TimeoutError()))
        self.assertEqual((method, reason), ("bm25", "TimeoutError"))
        self.assertFalse(breaker.open)

    def test_no_key_keeps_fallback_reason(self, bm25, _reg):
        _, method, reason = retrieve_once(FakeConn(), "q", CONFIG, None, Breaker())
        self.assertEqual((method, reason), ("bm25", "RuntimeError"))


if __name__ == "__main__":
    unittest.main()
