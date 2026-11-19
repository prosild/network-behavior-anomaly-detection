"""실습망 에이전트 실행의 사건별 실패 격리(scripts/live_agent.py run_two_phases).

zeek-ad 환경에서 실행한다: python -m unittest tests.test_live_agent -v
확인하는 것:
- 1차에서 실패한 사건은 2차를 건너뛰고, 나머지 사건은 1차·2차를 모두 돈다.
- 2차에서 실패한 사건이 있어도 뒤 사건의 2차는 돈다.
- 실패 목록에 단계와 오류 종류가 남는다.
- 감시 프로그램(scripts/live_watcher.py)은 에이전트가 실패한 캡처를 새 파일 없이도 agent_retries번까지 다시 부른다.
"""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from live_agent import revision_for_job, run_two_phases  # noqa: E402
from live_watcher import agent_retry_targets, note_agent_result  # noqa: E402

TODO = [f"lab-20261118|10.10.0.{i}|originator|1" for i in (1, 2, 3)]


class TwoPhaseTest(unittest.TestCase):
    def run_with(self, fail):
        calls = []

        def run_phase(command, iid):
            calls.append((command, iid))
            if (command, iid) in fail:
                raise KeyError("send_recommendation")
            return ["node"], ([] if command == "continue" else ["write_report"])

        failed = run_two_phases(TODO, run_phase, 0.0, log=lambda *a, **k: None)
        return calls, failed

    def test_all_succeed(self):
        calls, failed = self.run_with(set())
        self.assertEqual(failed, {})
        self.assertEqual([c for c, _ in calls], ["start"] * 3 + ["continue"] * 3)

    def test_phase1_failure_skips_only_that_incident(self):
        calls, failed = self.run_with({("start", TODO[0])})
        self.assertEqual(list(failed), [TODO[0]])
        self.assertTrue(failed[TODO[0]].startswith("1차 KeyError"))
        self.assertEqual([i for c, i in calls if c == "start"], TODO)            # 뒤 사건의 1차도 돈다
        self.assertEqual([i for c, i in calls if c == "continue"], TODO[1:])     # 실패한 사건만 2차를 건너뛴다

    def test_phase2_failure_does_not_block_later_incidents(self):
        calls, failed = self.run_with({("continue", TODO[1])})
        self.assertEqual(list(failed), [TODO[1]])
        self.assertTrue(failed[TODO[1]].startswith("2차"))
        self.assertEqual([i for c, i in calls if c == "continue"], TODO)


class WatcherRetryTest(unittest.TestCase):
    def test_retries_stop_after_limit(self):
        failures, runs = {}, 0
        note_agent_result(failures, "lab-1", 1, fresh=True)           # 새 다시 계산 뒤 첫 실패
        while agent_retry_targets(failures, [], retries=2):
            runs += 1
            note_agent_result(failures, "lab-1", 1, fresh=False)
        self.assertEqual(runs, 2)                                     # 다시 시도는 2번까지

    def test_success_clears_and_fresh_resets(self):
        failures = {"lab-1": 3}
        self.assertEqual(agent_retry_targets(failures, [], retries=2), [])
        note_agent_result(failures, "lab-1", 1, fresh=True)           # 새 파일로 다시 계산했으면 다시 센다
        self.assertEqual(agent_retry_targets(failures, [], retries=2), ["lab-1"])
        self.assertEqual(agent_retry_targets(failures, ["lab-1"], retries=2), [])   # 방금 계산한 캡처는 거기서 이미 불렀다
        note_agent_result(failures, "lab-1", 0, fresh=False)
        self.assertEqual(failures, {})


class RevisionForJobTest(unittest.TestCase):
    """작업의 리비전 폴더는 입력 지문으로 찾는다(묶음을 바꿔 다시 채점한 작업도, 단계 7)."""

    def test_match_by_input_fingerprint(self):
        import json
        import tempfile
        from zeek_ad.worker import input_fingerprint
        with tempfile.TemporaryDirectory() as tmp:
            cap = Path(tmp) / "lab-x"
            shas = {}
            for rev, n in (("rev-0001-aaaaaaaa", 1), ("rev-0002-bbbbbbbb", 2)):
                d = cap / rev
                for sub in ("gold", "graph"):
                    (d / sub).mkdir(parents=True)
                    (d / sub / "manifest.json").write_text(json.dumps({"n": n, "sub": sub}))
                (d / "bounds.json").write_text(json.dumps({"n": n}))
                (d / "worker-inputs.json").write_text(json.dumps({"sets": {"live": {
                    "gold_dir": str(d / "gold"), "graph_dir": str(d / "graph"), "bounds": str(d / "bounds.json")}}}))
                shas[rev] = input_fingerprint(d / "gold", d / "graph", d / "bounds.json", "lab-x")[0]
            (cap / "rev-0003-cccccccc").mkdir()                       # 끊긴 리비전(입력 정의 없음)은 무시
            self.assertEqual(revision_for_job(cap, "lab-x", shas["rev-0001-aaaaaaaa"]).name, "rev-0001-aaaaaaaa")
            self.assertEqual(revision_for_job(cap, "lab-x", shas["rev-0002-bbbbbbbb"]).name, "rev-0002-bbbbbbbb")
            self.assertIsNone(revision_for_job(cap, "lab-x", "0" * 64))


if __name__ == "__main__":
    unittest.main()
