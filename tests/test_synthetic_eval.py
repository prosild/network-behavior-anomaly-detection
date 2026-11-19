import unittest

from zeek_ad.synthetic_eval import as_capture, evaluate_day, summarize

# 규칙 확인용 가짜 예제다. 실제 점수가 아니다.
SHA = {"syn": "0" * 64}


def win(start_min, score, asset="10.0.0.1", role="originator"):
    return {"capture_id": "syn", "asset_id": asset, "role": role, "window_start": start_min * 60, "score": score}


def truth(ep, start_min, asset="10.0.0.1", role="originator", cap="syn"):
    return {"episode_id": ep, "capture_id": cap, "asset_id": asset, "role": role, "window_start": start_min * 60}


class SyntheticDayTest(unittest.TestCase):
    def setUp(self):
        # CIC 공격(자산 .2)이 1위, 합성 공격(자산 .1)이 2위, 오탐(자산 .3)이 3위.
        self.windows = [win(0, 9, asset="10.0.0.2"), win(0, 8), win(60, 7, asset="10.0.0.3"), win(120, 1)]
        self.syn = [truth("syn-a", 0)]
        self.cic = as_capture([truth("cic-1", 0, asset="10.0.0.2", cap="cic")], "syn")

    def test_main_queue_drops_cic_incidents(self):
        r = evaluate_day(self.windows, 5, SHA, self.syn, {"syn-a"}, self.cic, {"cic-1"})
        self.assertEqual(r["excluded_cic_incidents"], 1)
        self.assertEqual(r["excluded_with_synthetic"], 0)
        self.assertEqual(r["main"]["best_rank"]["syn-a"], 1)  # CIC 사건을 빼면 1위
        self.assertEqual(r["all"]["best_rank"]["syn-a"], 2)
        self.assertEqual(r["main"]["recall"][5]["matched"], 1)

    def test_uncertain_cic_episode_is_not_excluded(self):
        r = evaluate_day(self.windows, 5, SHA, self.syn, {"syn-a"}, self.cic, set())
        self.assertEqual(r["excluded_cic_incidents"], 0)
        self.assertEqual(r["main"]["best_rank"]["syn-a"], 2)

    def test_missed_episode_diagnosis(self):
        r = evaluate_day(self.windows, 8.5, SHA, self.syn, {"syn-a"}, self.cic, {"cic-1"})
        self.assertEqual(r["diagnosis"]["syn-a"], {"max_window_score": 8, "candidate": False})
        self.assertIsNone(r["main"]["best_rank"]["syn-a"])

    def test_summary_pools_days_and_patterns(self):
        day = evaluate_day(self.windows, 5, SHA, self.syn, {"syn-a"}, self.cic, {"cic-1"})
        s = summarize({"syn": day}, {"syn-a": "beacon"})
        self.assertEqual(s["main"][10]["matched"], 1)
        self.assertEqual(s["patterns"]["beacon"]["syn"]["hit_at_10"], 1)


if __name__ == "__main__":
    unittest.main()
