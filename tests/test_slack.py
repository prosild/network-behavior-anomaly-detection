"""Slack 메시지 만들기(zeek_ad.slack) 시험. 표준 라이브러리만 쓴다(DB 기록은 시험하지 않는다).

실행: python3 -m unittest tests.test_slack -v
"""

from datetime import datetime, timezone
import json
import unittest

from types import SimpleNamespace

from zeek_ad.slack import alert_thread, daily_summary, escape, group_alert, incident_message

CONFIG = {"channel": "#soc", "api_base_url": "http://dash.local", "max_claims": 2, "max_text_chars": 60}
INCIDENT = {"job_id": 4, "incident_id": "x", "capture_id": "cic17-fri", "queue_rank": 1, "asset": "192.168.10.50",
            "role": "responder", "first_start": datetime(2017, 7, 7, 18, 55, tzinfo=timezone.utc),
            "last_end": datetime(2017, 7, 7, 19, 20, tzinfo=timezone.utc), "picked_by": "tgn_recon",
            "also_flagged_by": ["tail_rarity_v2"]}
DECISION = {"policy": {"choice": "send", "mandatory": True, "reasons": ["queue_rank 1 <= 5"]},
            "llm_choice": "send", "decision_model": {"choice": "send"}}


class EscapeTest(unittest.TestCase):
    def test_slack_control_sequences_become_text(self):
        self.assertEqual(escape("<!channel> <http://evil|ok> a&b"), "&lt;!channel&gt; &lt;http://evil|ok&gt; a&amp;b")

    def test_llm_text_cannot_inject_mentions_or_links(self):
        report = {"report_version": "llm-report.v1",
                  "observation_summary": "정상 <!channel> 확인 <http://evil.example|대시보드>",
                  "claims": [{"claim": "<@U123> 1242건", "fact_ids": ["F09"]}]}
        body = json.dumps(incident_message(INCIDENT, report, "llm", DECISION, CONFIG), ensure_ascii=False)
        self.assertNotIn("<!channel>", body)
        self.assertNotIn("<http://evil", body)
        self.assertNotIn("<@U123>", body)

    def test_long_text_is_cut_and_pseudonym_legend_present(self):
        report = {"report_version": "template.v1", "observation_summary": "가" * 500, "claims": []}
        msg = incident_message(INCIDENT, report, "template", DECISION, CONFIG)
        body = json.dumps(msg, ensure_ascii=False)
        self.assertIn("H = 192.168.10.50", body)
        summary = [b for b in msg["blocks"] if "text" in b and "관측 요약" in b["text"]["text"]][0]
        self.assertLessEqual(len(summary["text"]["text"]), len("*관측 요약*\n") + 60)


class SummaryTest(unittest.TestCase):
    def test_unsent_incidents_are_listed(self):
        msg = daily_summary({"job_id": 1, "capture_id": "cic17-wed"}, {"queue": 252, "decided": 10, "sent": 9},
                            [(20, "192.168.10.3", "originator")], CONFIG)
        body = json.dumps(msg, ensure_ascii=False)
        self.assertIn("보내지 않음 1건", body)
        self.assertIn("20위 192.168.10.3", body)
        self.assertIn("전송 판단을 하지 않은 사건 242건", body)


RULE = {"window_minutes": 60, "realert_minutes": 30}
M = 60


def alert(iid, start_min, end_min, parent=None, broadcast=False, closed=False):
    return {"incident_id": iid, "thread_parent": parent, "reply_broadcast": broadcast,
            "first_start": start_min * M, "last_end": end_min * M, "root_closed": closed}


class AlertGroupingTest(unittest.TestCase):
    """같은 자산 알림 묶음(DD-010 결정 5): 60분 안 미해결 묶음에 스레드 답글, 30분마다 채널 재알림."""

    def test_first_alert_is_root(self):
        self.assertEqual(group_alert([], 0, RULE), (None, False))

    def test_reply_then_realert_after_30_minutes(self):
        root = [alert("A", 0, 10)]
        self.assertEqual(group_alert(root, 20 * M, RULE), ("A", False))      # 머리 알림 20분 뒤: 답글만
        self.assertEqual(group_alert(root, 40 * M, RULE), ("A", True))       # 30분 지남: 채널에도 띄운다

    def test_gap_over_60_minutes_starts_new_root(self):
        self.assertEqual(group_alert([alert("A", 0, 10)], 71 * M, RULE), (None, False))
        self.assertEqual(group_alert([alert("A", 0, 10)], 70 * M, RULE), ("A", True))   # 끝에서 정확히 60분은 같은 묶음

    def test_closed_root_starts_new_root(self):
        self.assertEqual(group_alert([alert("A", 0, 10, closed=True)], 20 * M, RULE), (None, False))

    def test_window_slides_with_replies_and_realert_counts_broadcasts(self):
        # 머리 0~5분, 재알림 답글 33~38분 → 새 사건 80분: 마지막 활동(38분)에서 60분 안, 마지막 채널 알림(33분)에서 30분 넘음
        hist = [alert("A", 0, 5), alert("B", 33, 38, parent="A", broadcast=True)]
        self.assertEqual(group_alert(hist, 80 * M, RULE), ("A", True))
        hist[1]["reply_broadcast"] = False                                   # 재알림이 없었다면 기준은 머리(0분)
        self.assertEqual(group_alert(hist, 50 * M, RULE), ("A", True))
        self.assertEqual(group_alert([alert("A", 0, 5), alert("B", 33, 38, parent="A", broadcast=True)], 50 * M, RULE),
                         ("A", False))                                       # 33분에 채널에 띄웠으니 50분은 답글만

    def test_root_followup_row_counts_as_root(self):
        # 머리 사건의 뒤 알림 행은 thread_parent가 자기 자신이다. 그래도 머리(채널에 올라감)로 본다
        hist = [alert("A", 0, 10, parent="A")]
        self.assertEqual(group_alert(hist, 35 * M, RULE), ("A", True))

    def test_latest_open_group_wins(self):
        hist = [alert("A", 0, 10), alert("C", 30, 50)]                       # 둘 다 열려 있으면 최근 활동 묶음
        self.assertEqual(group_alert(hist, 55 * M, RULE)[0], "C")


class FakeConn:
    def __init__(self, *results):
        self.results, self.sql = list(results), []

    def execute(self, sql, params=None):
        self.sql.append(" ".join(sql.split()))
        value = self.results.pop(0)
        return SimpleNamespace(fetchone=lambda: value, fetchall=lambda: value)


class AlertThreadTest(unittest.TestCase):
    def test_followups_join_the_incidents_thread(self):
        # 이미 알린 사건의 뒤 알림(LLM 보고서·상태 변경)은 그 사건이 속한 스레드, 채널에는 안 띄운다
        self.assertEqual(alert_thread(FakeConn((1, None)), 1, "I", "llm-report.v1", RULE), ("I", False))
        self.assertEqual(alert_thread(FakeConn((2, "A")), 1, "I", "status:closed", RULE), ("A", False))

    def test_status_of_never_alerted_incident_is_not_grouped(self):
        conn = FakeConn((0, None))
        self.assertEqual(alert_thread(conn, 1, "I", "status:investigating", RULE), (None, False))
        self.assertEqual(len(conn.sql), 1)

    def test_new_incident_uses_previous_alerts(self):
        prev = [("A", None, False, 0.0, 600.0, False)]
        conn = FakeConn((0, None), ("10.10.0.50", "originator", 1200.0), prev)
        self.assertEqual(alert_thread(conn, 2, "I", "template.v1", RULE), ("A", False))


if __name__ == "__main__":
    unittest.main()
