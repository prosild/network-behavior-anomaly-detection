"""실습망에서 보고서를 (다시) 만들 사건 고르기(zeek_ad.agent_store.report_reason, DD-016 결정 3).

psycopg가 필요하므로 zeek-ad 환경에서 실행한다: python -m unittest tests.test_agent_store -v
확인하는 것:
- 보고서가 없는 사건은 새로 처리한다.
- 이전 작업 보고서와 창 목록이 같으면 건너뛰고, 창이 늘어났으면 다시 처리한다.
- 이 작업에서 이미 처리한 사건은 다시 하지 않는다.
- 보고서는 있는데 전송 판단이 없으면(판단·전송 단계에서 실패) 다시 처리한다.
- 호출 실패 사건을 다시 만들 때(--redo-failed-calls) 이미 고른 사건은 겹치지 않는다.
"""

from datetime import datetime, timedelta, timezone
import unittest

from zeek_ad.agent_store import report_reason, with_redo

T0 = datetime(2026, 11, 18, 9, 40, tzinfo=timezone.utc)
W = [T0 + timedelta(minutes=5 * i) for i in range(3)]


class ReportReasonTest(unittest.TestCase):
    def test_no_report_is_new(self):
        self.assertEqual(report_reason(31, W[:1], None, None), "new")

    def test_same_windows_skipped(self):
        self.assertIsNone(report_reason(31, W[:2], 27, W[:2]))

    def test_grown_incident_is_changed(self):
        # 09:40 창(ping)으로 보고서를 만든 뒤 09:45 창(nmap)이 이어 붙은 경우(2026-11-18 VM 시험)
        self.assertEqual(report_reason(31, W[:2], 27, W[:1]), "changed")

    def test_shrunk_incident_is_changed(self):
        self.assertEqual(report_reason(31, W[:1], 27, W[:2]), "changed")

    def test_already_done_in_this_job(self):
        self.assertIsNone(report_reason(31, W[:2], 31, W[:1]))

    def test_report_without_decision_is_retried(self):
        self.assertEqual(report_reason(31, W[:2], 31, W[:2], decided=False), "retry")
        self.assertEqual(report_reason(31, W[:2], 27, W[:2], decided=False), "retry")

    def test_grown_wins_over_retry(self):
        self.assertEqual(report_reason(31, W[:2], 27, W[:1], decided=False), "changed")


class RedoTest(unittest.TestCase):
    def test_redo_appends_only_unpicked(self):
        picked = [("a", "new"), ("b", "retry")]
        self.assertEqual(with_redo(picked, ["b", "c"]), [("a", "new"), ("b", "retry"), ("c", "redo")])


if __name__ == "__main__":
    unittest.main()
