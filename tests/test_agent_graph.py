"""LangGraph 흐름(zeek_ad.agent_graph)의 경로 시험. DB·LLM·판단 모델 대신 가짜 함수를 쓴다(네트워크 없음).

langgraph가 필요하므로 zeek-ad 환경에서 실행한다: python -m unittest tests.test_agent_graph -v
확인하는 것:
- 판단 모델이 need_more_evidence를 고르면 추가 근거를 한 번 더하고 다시 판단한다. 반복 상한(1회)을 넘지 않는다.
- analyst_review면 interrupt로 멈추고, 같은 thread_id로 재개하면 결정을 기록하고 끝난다.
- 판단 모델 호출이 실패해도 흐름은 멈추지 않고 정책 규칙대로 전송을 정한다.
- 정책 규칙이 보냄이면 LLM 보고서 전에 템플릿 알림을 먼저 기록하고, LLM 보고서가 나오면 한 번 더 기록한다(Q47).
- 이전 작업에서 이미 알린 사건(늘어나 다시 처리하는 사건)은 보고서는 다시 쓰고 Slack에는 기록하지 않는다(DD-016 결정 4).
- LLM 보고서나 판단 모델이 한도 초과(429)면 판단 없이 끝내고, 같은 실행의 다음 사건은 LLM을 부르지 않는다(zeek_ad.quota).
"""

from datetime import datetime, timezone
import unittest
from unittest import mock

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from zeek_ad import agent_graph
from zeek_ad.quota import Breaker, QuotaExhausted

FACTS = [{"id": "F01", "name": "queue_rank", "value": 3},
         {"id": "F02", "name": "also_flagged_by_models", "value": ["tail_rarity_v2"]},
         {"id": "F03", "name": "connection_count", "value": 12}]
POLICY = {"policy_id": "policy.v1", "mandatory_send": {"max_queue_rank": 5, "min_flagging_models": 2},
          "otherwise": "hold"}


class FakeConn:
    """execute 호출을 기록하고, 그래프가 읽는 두 질의에만 고정 값을 돌려준다."""

    def __init__(self):
        self.calls = []
        self.status = "open"

    def execute(self, sql, params=()):
        self.calls.append((" ".join(sql.split()), params))
        result = mock.Mock()
        t = datetime(2017, 7, 7, 12, 0, tzinfo=timezone.utc)
        if "first_start, last_end" in sql:
            result.fetchone.return_value = (t, t)
        elif "coalesce((SELECT status" in sql:
            result.fetchone.return_value = (self.status,)
        else:
            result.fetchone.return_value = None
        if "transition_incident" in sql:
            self.status = params[2]
        result.fetchall.return_value = [(7,)]
        return result


def decision(choice, error=None):
    return {"model": "gemini-decision-1", "choice": choice, "error": error, "seconds": 0.1, "confidence": 0.4,
            "probabilities": None if choice is None else {choice: 0.4}}


class GraphPathTest(unittest.TestCase):
    def setUp(self):
        self.conn = FakeConn()
        llm_report = {"observation_summary": "요약", "claims": [],
                      "send_recommendation": {"choice": "hold", "reason": "r", "fact_ids": ["F03"]}}
        patches = {
            "collect_incident": mock.Mock(return_value={"queue_rank": 3, "model_windows": {}}),
            "collect_evidence": mock.Mock(return_value={"connection_count": 12}),
            "collect_baseline": mock.Mock(return_value=[["baseline_windows",
                                                         {"incident_windows": 1, "baseline_windows": 3}]]),
            "facts_from_parts": mock.Mock(side_effect=lambda *a: [dict(f) for f in FACTS]),
            "retrieve_once": mock.Mock(return_value=([[{"attack_id": "T1046", "name": "Network Service Discovery"}]],
                                                     "gemini", None)),
            "template_report": mock.Mock(return_value={"report_version": "template.v1"}),
            "call_llm": mock.Mock(return_value={"report": llm_report, "model_version": "fake", "error": None}),
            "guarded_final_report": mock.Mock(side_effect=lambda call, inp, tpl: (
                {"report_version": "llm-report.v1", "observation_summary": "요약"}, "llm",
                {"passed": True, "reason": None, "problems": []}, call)),
            "pseudonym_map": mock.Mock(return_value={"H": "192.168.10.5"}),
            "save_report": mock.Mock(), "save_decision": mock.Mock(),
            "record_delivery": mock.Mock(return_value=True),
            "alerted_before": mock.Mock(return_value=False),
            "incident_row": mock.Mock(return_value={}), "incident_message": mock.Mock(return_value={}),
            "status_message": mock.Mock(return_value={}),
            "context_facts": mock.Mock(side_effect=lambda conn, ctx, state: [
                {"id": f"F{len(state['llm_input']['facts']) + 1:02d}", "name": "context.extra", "value": 1}]),
            "call_decision": mock.Mock(),
        }
        self.mocks = patches
        for name, m in patches.items():
            p = mock.patch.object(agent_graph, name, m)
            p.start()
            self.addCleanup(p.stop)
        ctx = mock.Mock(nets=["192.168.10.0/24"], retrieval={}, api_key=None)
        self.res = {"conn": self.conn, "ctx": ctx, "client_llm": None, "client_decision": None,
                    "report_config": {}, "system_prompt": "", "send_config": {"policy": POLICY, "decision_model": {}},
                    "slack_config": {}, "source": "test"}

    def run_graph(self, checkpointer=None, thread="t1"):
        graph = agent_graph.build_graph(self.res, checkpointer)
        cfg = {"configurable": {"thread_id": thread}}
        state = graph.invoke({"job_id": 1, "incident_id": "cic17-fri|192.168.10.5|originator|1499441700"}, cfg)
        return graph, cfg, state

    def nodes(self, state):
        return [t["node"] for t in state["trace"]]

    def test_more_evidence_once_then_deliver(self):
        self.mocks["call_decision"].side_effect = [decision("need_more_evidence"), decision("need_more_evidence")]
        _, _, state = self.run_graph()
        order = self.nodes(state)
        self.assertEqual(order.count("decide"), 2)
        self.assertEqual(order.count("more_evidence"), 1)        # 반복 상한 1회
        self.assertEqual(order[-1], "deliver")
        second_input = self.mocks["call_decision"].call_args_list[1].args[2]
        self.assertEqual(second_input["facts"][-1]["name"], "context.extra")   # 두 번째 판단은 추가 근거를 본다

    def test_analyst_review_interrupts_and_resumes(self):
        self.mocks["call_decision"].side_effect = [decision("analyst_review")]
        graph, cfg, state = self.run_graph(InMemorySaver())
        snapshot = graph.get_state(cfg)
        self.assertEqual(snapshot.next, ("analyst_review",))
        self.assertEqual(state["__interrupt__"][0].value["reason"], "decision_model=analyst_review")
        state = graph.invoke(Command(resume={"action": "dismiss", "analyst": "a1", "note": "오탐"}), cfg)
        self.assertEqual(graph.get_state(cfg).next, ())
        self.assertEqual(state["review"]["action"], "dismiss")
        updates = [c for c in self.conn.calls if c[0].startswith("UPDATE analyst_review")]
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0][1][0], "dismiss")
        inserts = [c for c in self.conn.calls if c[0].startswith("INSERT INTO analyst_review")]
        self.assertTrue(all("ON CONFLICT DO NOTHING" in c[0] for c in inserts))   # 재개 때 다시 돌아도 한 행
        # dismiss는 확인 중을 거쳐 종료(오탐)로 두 번 바꾸고, 바꿀 때마다 Slack 후속 알림을 기록한다
        moves = [c[1][2:6] for c in self.conn.calls if "transition_incident" in c[0]]
        self.assertEqual(moves, [("investigating", "a1", "오탐", None), ("closed", "a1", "오탐", "false_positive")])
        self.assertEqual(self.nodes(state)[-1], "apply_status")
        versions = [c.args[3] for c in self.mocks["record_delivery"].call_args_list]
        self.assertIn("status:investigating", versions)
        self.assertIn("status:closed", versions)

    def test_confirm_skips_if_dashboard_already_moved(self):
        self.mocks["call_decision"].side_effect = [decision("analyst_review")]
        graph, cfg, _ = self.run_graph(InMemorySaver(), thread="t2")
        self.conn.status = "investigating"                        # 그사이 대시보드에서 먼저 확인 중으로 바꿈
        state = graph.invoke(Command(resume={"action": "confirm", "analyst": "a1", "note": "확인"}), cfg)
        self.assertFalse([c for c in self.conn.calls if "transition_incident" in c[0]])
        self.assertEqual(state["trace"][-1]["transitions"], [])

    def test_decision_failure_uses_policy(self):
        self.mocks["call_decision"].side_effect = [decision(None, error="call: TimeoutError")]
        _, _, state = self.run_graph()
        self.assertEqual(self.nodes(state)[-1], "deliver")
        self.assertTrue(state["shadow"]["would_send"])            # 큐 3위라 필수 전송(정책 규칙)
        self.assertTrue(state["shadow"]["decision_model_failed"])
        self.assertFalse(state.get("review_reason"))

    def test_llm_review_alone_does_not_wait(self):
        # LLM이 analyst_review를 골라도 판단 모델이 hold면 대기하지 않는다(Q49)
        self.mocks["call_llm"].return_value["report"]["send_recommendation"]["choice"] = "analyst_review"
        self.mocks["call_decision"].side_effect = [decision("hold")]
        _, _, state = self.run_graph()
        self.assertNotIn("analyst_review", self.nodes(state))
        self.assertEqual(state["shadow"]["llm"], "analyst_review")   # LLM 의견은 기록된다

    def test_hold_ends_without_review(self):
        self.mocks["call_decision"].side_effect = [decision("hold")]
        _, _, state = self.run_graph()
        self.assertNotIn("analyst_review", self.nodes(state))
        # 정책 규칙상 보냄이라 Slack 기록은 한다: 템플릿 알림 먼저, LLM 보고서 다음
        versions = [c.args[3] for c in self.mocks["record_delivery"].call_args_list]
        self.assertEqual(versions, ["template.v1", "llm-report.v1"])

    def test_early_alert_comes_before_llm_report(self):
        self.mocks["call_decision"].side_effect = [decision("send")]
        _, _, state = self.run_graph()
        order = self.nodes(state)
        self.assertLess(order.index("early_alert"), order.index("write_report"))
        early = self.mocks["incident_message"].call_args_list[0]
        self.assertIsNone(early.args[3]["decision_model"])        # 먼저 보낼 때는 정책 규칙만 안다

    def test_no_early_alert_when_policy_holds(self):
        self.mocks["facts_from_parts"].side_effect = lambda *a: [
            {"id": "F01", "name": "queue_rank", "value": 40},
            {"id": "F02", "name": "also_flagged_by_models", "value": []},
            {"id": "F03", "name": "connection_count", "value": 12}]
        self.mocks["call_decision"].side_effect = [decision("hold")]
        _, _, state = self.run_graph()
        self.mocks["record_delivery"].assert_not_called()       # 큐 40위, 한 모델: 정책 보류라 알림 없음


    def test_refreshed_incident_is_not_alerted_again(self):
        # 이전 작업에서 이미 알린 사건: 보고서·판단은 새로 쓰지만 Slack 기록(템플릿·LLM 모두)은 하지 않는다
        self.mocks["alerted_before"].return_value = True
        self.mocks["call_decision"].side_effect = [decision("send")]
        _, _, state = self.run_graph()
        self.mocks["record_delivery"].assert_not_called()
        self.mocks["save_report"].assert_called_once()
        self.mocks["save_decision"].assert_called_once()
        self.assertTrue(state["delivery"]["would_send"])          # 판단 기록은 그대로 남는다
        self.assertEqual(state["delivery"]["skipped"], "alerted_before")
        early = next(t for t in state["trace"] if t["node"] == "early_alert")
        self.assertEqual(early["slack_skipped"], "alerted_before")


    def test_llm_quota_stops_calls_for_the_rest_of_the_run(self):
        # 보고서 호출이 429: 템플릿만 남기고(앞 보고서는 덮지 않게) 판단 없이 끝낸다. 다음 사건은 LLM을 부르지 않는다
        breaker = self.res["llm_breaker"] = Breaker()

        def rate_limited(*args):
            breaker.trip("models.generate_content")
            return {"report": None, "model_version": None, "error": "call: QuotaExhausted"}

        self.mocks["call_llm"].side_effect = rate_limited
        graph = agent_graph.build_graph(self.res, InMemorySaver())
        for k, thread in enumerate(("a", "b"), 1):
            with self.assertRaises(QuotaExhausted):
                graph.invoke({"job_id": 1, "incident_id": f"cic17-fri|192.168.10.{k}|originator|1"},
                             {"configurable": {"thread_id": thread}})
            self.assertEqual(self.mocks["save_report"].call_count, k)
            self.assertFalse(self.mocks["save_report"].call_args.kwargs["overwrite"])
        self.assertEqual(self.mocks["call_llm"].call_count, 1)       # 두 번째 사건은 부르지 않았다
        self.mocks["call_decision"].assert_not_called()
        self.mocks["save_decision"].assert_not_called()              # 판단이 없으니 다음 실행이 다시 고른다
        self.assertEqual(self.mocks["record_delivery"].call_count, 2)   # 템플릿 알림(early_alert)은 둘 다 나갔다

    def test_decision_quota_leaves_no_decision(self):
        breaker = self.res["llm_breaker"] = Breaker()

        def rate_limited(*args):
            breaker.trip("decisions.create")
            return decision(None, error="call: RateLimitError")

        self.mocks["call_decision"].side_effect = rate_limited
        with self.assertRaises(QuotaExhausted):
            self.run_graph()
        self.assertTrue(self.mocks["save_report"].call_args.kwargs["overwrite"])   # LLM 보고서는 정상으로 썼다
        self.mocks["save_decision"].assert_not_called()

    def test_embedding_breaker_is_shared_across_incidents(self):
        self.mocks["call_decision"].side_effect = [decision("hold"), decision("hold")]
        graph = agent_graph.build_graph(self.res, InMemorySaver())
        for thread in ("a", "b"):
            graph.invoke({"job_id": 1, "incident_id": "cic17-fri|192.168.10.5|originator|1"},
                         {"configurable": {"thread_id": thread}})
        first, second = (c.args[4] for c in self.mocks["retrieve_once"].call_args_list)
        self.assertIs(first, second)

    def test_failed_thread_restarts_from_start(self):
        # live_agent.py 다시 시도: 2차(write_report)에서 실패한 thread에 같은 thread_id로 새 입력을 주면 처음부터 다시 돈다
        self.mocks["call_llm"].side_effect = [RuntimeError("일시 오류"), self.mocks["call_llm"].return_value]
        self.mocks["call_decision"].side_effect = [decision("hold")]
        graph = agent_graph.build_graph(self.res, InMemorySaver())
        cfg = {"configurable": {"thread_id": "1|x"}}
        start = {"job_id": 1, "incident_id": "cic17-fri|192.168.10.5|originator|1499441700"}
        graph.invoke(start, cfg, interrupt_after=["early_alert"])
        with self.assertRaises(RuntimeError):
            graph.invoke(None, cfg)
        graph.invoke(start, cfg, interrupt_after=["early_alert"])
        self.assertEqual(graph.get_state(cfg).next, ("write_report",))
        graph.invoke(None, cfg)
        self.assertEqual(graph.get_state(cfg).next, ())
        self.mocks["save_decision"].assert_called_once()
        self.assertEqual(self.mocks["collect_incident"].call_count, 2)   # 근거부터 다시 모았다

    def test_two_phase_sends_all_early_alerts_first(self):
        # 1차: 모든 사건을 early_alert 뒤에서 멈춘다. 2차: 같은 thread로 이어서 LLM 보고서까지(live_agent.py 방식).
        self.mocks["call_decision"].side_effect = [decision("send"), decision("send")]
        graph = agent_graph.build_graph(self.res, InMemorySaver())
        threads = [{"configurable": {"thread_id": t}} for t in ("a", "b")]
        for i, cfg in enumerate(threads):
            graph.invoke({"job_id": 1, "incident_id": f"cic17-fri|192.168.10.{i}|originator|1"}, cfg,
                         interrupt_after=["early_alert"])
            self.assertEqual(graph.get_state(cfg).next, ("write_report",))
        for cfg in threads:
            graph.invoke(None, cfg)
            self.assertEqual(graph.get_state(cfg).next, ())
        versions = [c.args[3] for c in self.mocks["record_delivery"].call_args_list]
        self.assertEqual(versions, ["template.v1", "template.v1", "llm-report.v1", "llm-report.v1"])


if __name__ == "__main__":
    unittest.main()
