"""분석가 검토 결정으로 멈춘 흐름 재개(zeek_ad.review_resume, DD-019) 시험.

가짜 그래프·DB로 규칙을 보고, 작은 실제 LangGraph 그래프(interrupt → Command(resume))로 재개 동작을 확인한다.
zeek-ad 환경에서 실행한다(langgraph 필요). 실행: python -m unittest tests.test_review_resume -v
"""

from types import SimpleNamespace
from typing import TypedDict
import unittest

from zeek_ad.review_resume import decided_reviews, resume_one

REVIEW = {"job_id": 42, "incident_id": "lab-x|10.10.0.102|originator|1", "action": "dismiss", "analyst": "a1",
          "note": "재생한 정상"}


class FakeConn:
    def __init__(self, rows=()):
        self.rows, self.calls = list(rows), []

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))
        return SimpleNamespace(fetchall=lambda: self.rows)

    def updates(self):
        return [(s, p) for s, p in self.calls if s.startswith("UPDATE")]


class FakeGraph:
    def __init__(self, waiting=True, error=None, still_waiting=False):
        self.next = ("analyst_review",) if waiting else ()
        self.error, self.still_waiting, self.resumed_with = error, still_waiting, None

    def get_state(self, cfg):
        return SimpleNamespace(next=self.next)

    def stream(self, command, cfg, stream_mode):
        self.resumed_with = command
        if self.error:
            raise self.error
        if not self.still_waiting:
            self.next = ()
        yield {"apply_status": {}}


def command(resume):
    return ("Command", resume)


class ResumeRulesTest(unittest.TestCase):
    def test_decided_reviews_query(self):
        conn = FakeConn([(42, "iid", "dismiss", "a1", None)])
        self.assertEqual(decided_reviews(conn), [{"job_id": 42, "incident_id": "iid", "action": "dismiss",
                                                  "analyst": "a1", "note": None}])
        sql = conn.calls[0][0]
        for part in ("action IS NOT NULL", "resumed_at IS NULL", "resume_error IS NULL"):
            self.assertIn(part, sql)

    def test_resumed(self):
        conn, graph = FakeConn(), FakeGraph()
        self.assertEqual(resume_one(graph, conn, REVIEW, command), "resumed")
        self.assertEqual(graph.resumed_with, ("Command", {"action": "dismiss", "analyst": "a1", "note": "재생한 정상"}))
        self.assertIn("SET resumed_at = now()", conn.updates()[0][0])

    def test_not_waiting_is_marked_and_not_resumed(self):
        conn, graph = FakeConn(), FakeGraph(waiting=False)                 # thread가 없거나 이미 끝났다
        self.assertEqual(resume_one(graph, conn, REVIEW, command), "not_waiting")
        self.assertIsNone(graph.resumed_with)
        self.assertIn("resume_error = 'not_waiting'", conn.updates()[0][0])

    def test_failure_keeps_only_error_type(self):
        conn = FakeConn()
        graph = FakeGraph(error=ValueError("10.10.0.102 관련 오류"))      # 오류 문장에 IP가 섞여도 남기지 않는다
        self.assertEqual(resume_one(graph, conn, REVIEW, command), "failed")
        sql, params = conn.updates()[0]
        self.assertIn("SET resume_error = %s", sql)
        self.assertEqual(params[0], "ValueError")
        self.assertFalse(any("resumed_at" in s for s, _ in conn.updates()))

    def test_still_waiting_after_resume_is_failure(self):
        conn = FakeConn()
        self.assertEqual(resume_one(FakeGraph(still_waiting=True), conn, REVIEW, command), "failed")
        self.assertEqual(conn.updates()[0][1][0], "RuntimeError")


class RealGraphTest(unittest.TestCase):
    """실제 LangGraph: 노드 안 interrupt()로 멈춘 thread를 같은 thread_id로 재개한다(그래프 구조만 본떴다)."""

    def test_interrupt_then_resume(self):
        from langgraph.checkpoint.memory import InMemorySaver
        from langgraph.graph import END, START, StateGraph
        from langgraph.types import Command, interrupt

        class S(TypedDict, total=False):
            review: dict
            status: str

        def analyst_review(state):
            return {"review": interrupt({"ask": "confirm 또는 dismiss"})}

        def apply_status(state):
            return {"status": "closed" if state["review"]["action"] == "dismiss" else "investigating"}

        g = StateGraph(S)
        g.add_node("analyst_review", analyst_review)
        g.add_node("apply_status", apply_status)
        g.add_edge(START, "analyst_review")
        g.add_edge("analyst_review", "apply_status")
        g.add_edge("apply_status", END)
        graph = g.compile(checkpointer=InMemorySaver())
        cfg = {"configurable": {"thread_id": f"{REVIEW['job_id']}|{REVIEW['incident_id']}"}}
        list(graph.stream({}, cfg, stream_mode="updates"))
        self.assertEqual(graph.get_state(cfg).next, ("analyst_review",))      # 검토 대기로 멈췄다

        conn = FakeConn()
        self.assertEqual(resume_one(graph, conn, REVIEW, Command), "resumed")
        state = graph.get_state(cfg)
        self.assertEqual((state.next, state.values["status"], state.values["review"]["analyst"]), ((), "closed", "a1"))
        # 다른 thread(재개할 흐름이 없음)는 not_waiting
        other = dict(REVIEW, job_id=99)
        self.assertEqual(resume_one(graph, FakeConn(), other, Command), "not_waiting")


if __name__ == "__main__":
    unittest.main()
