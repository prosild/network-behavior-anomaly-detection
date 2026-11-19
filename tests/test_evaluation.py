import unittest

from zeek_ad.evaluation import (
    bootstrap_recall_ci, build_incidents, pooled_hits, episode_edges, max_matching, percentile, rank_queue, recall_at_n,
    tie_key, tie_sensitivity,
)

# 규칙 확인용 가짜 예제다. 실제 CIC 점수가 아니다.
SHA = {"cap": "0" * 64}


def win(start_min, score, asset="10.0.0.1", role="responder", cap="cap"):
    return {"capture_id": cap, "asset_id": asset, "role": role, "window_start": start_min * 60, "score": score}


def truth(ep, start_min, asset="10.0.0.1", role="responder", cap="cap"):
    return {"episode_id": ep, "capture_id": cap, "asset_id": asset, "role": role, "window_start": start_min * 60}


class PercentileTest(unittest.TestCase):
    def test_linear_interpolation_like_numpy(self):
        self.assertAlmostEqual(percentile([1, 2, 3, 4], 95), 3.85)
        self.assertEqual(percentile([5], 95), 5)


class IncidentTest(unittest.TestCase):
    def test_consecutive_windows_merge_and_gap_splits(self):
        ws = [win(0, 5), win(5, 7), win(10, 1), win(15, 6)]  # 10분 창은 후보가 아니라 끊긴다
        incs = build_incidents(ws, 5, SHA)
        self.assertEqual([i.windows for i in incs], [(0, 300), (900,)])
        self.assertEqual(incs[0].score, 7)  # 구성 창의 최댓값

    def test_threshold_tie_is_candidate(self):
        self.assertEqual(len(build_incidents([win(0, 5)], 5, SHA)), 1)

    def test_thirty_minute_cap_starts_new_incident(self):
        ws = [win(m, 9) for m in range(0, 40, 5)]  # 0~35분, 8개 창
        incs = build_incidents(ws, 1, SHA)
        self.assertEqual([len(i.windows) for i in incs], [6, 2])

    def test_assets_and_roles_do_not_merge(self):
        ws = [win(0, 9), win(5, 9, role="originator"), win(5, 9, asset="10.0.0.2")]
        self.assertEqual(len(build_incidents(ws, 1, SHA)), 3)


class RankTest(unittest.TestCase):
    def test_ties_follow_fixed_hash(self):
        incs = build_incidents([win(0, 9, asset="a"), win(0, 9, asset="b"), win(0, 10, asset="c")], 1, SHA)
        queue = rank_queue(incs)
        self.assertEqual(queue[0].asset_id, "c")
        expected = sorted(["a", "b"], key=lambda a: tie_key(SHA["cap"], a, "responder", 0, 300))
        self.assertEqual([i.asset_id for i in queue[1:]], expected)


class RecallTest(unittest.TestCase):
    def setUp(self):
        # 사건 X는 에피소드 A·B 모두와 겹치고, 사건 Y는 A와만 겹친다.
        ws = [win(0, 9, asset="x"), win(0, 8, asset="y"), win(0, 7, asset="z")]
        self.queue = rank_queue(build_incidents(ws, 1, SHA))
        tw = [truth("A", 0, asset="x"), truth("B", 0, asset="x"), truth("A", 0, asset="y"),
              truth("U", 0, asset="z")]
        self.edges = episode_edges(self.queue, tw, {"A", "B"})  # U는 uncertain이라 간선이 없다

    def test_one_to_one_matching_is_maximum(self):
        r = recall_at_n(self.queue, 2, self.edges, {"A", "B"})
        self.assertEqual(r["matched"], 2)  # X→B, Y→A가 최대 대응
        self.assertEqual(r["recall"], 1.0)

    def test_duplicate_alert_gives_no_extra_recall(self):
        r = recall_at_n(self.queue, 1, self.edges, {"A", "B"})
        self.assertEqual(r["matched"], 1)
        self.assertEqual(r["covered"], 2)  # 보조 지표는 한 사건이 둘을 포함한 것을 보여 준다

    def test_uncertain_episode_is_not_an_edge(self):
        z = [i for i in self.queue if i.asset_id == "z"][0]
        self.assertEqual(self.edges[z.incident_id], set())

    def test_matching_is_deterministic(self):
        edges = {"i1": {"A", "B"}, "i2": {"A", "B"}}
        self.assertEqual(max_matching(edges), max_matching(dict(reversed(list(edges.items())))))


class TieSensitivityTest(unittest.TestCase):
    def test_boundary_ties_are_sampled(self):
        ws = [win(0, 9, asset=a) for a in "abcd"]  # 4개 모두 동점, N=2
        queue = rank_queue(build_incidents(ws, 1, SHA))
        edges = episode_edges(queue, [truth("A", 0, asset="a")], {"A"})
        t = tie_sensitivity(queue, 2, edges, {"A"})
        self.assertEqual((t["tie_size"], t["open_slots"]), (4, 2))
        self.assertAlmostEqual(t["recall"]["mean"], 0.5, delta=0.05)  # a가 뽑힐 확률 2/4

    def test_no_boundary_tie_returns_none(self):
        queue = rank_queue(build_incidents([win(0, 9, asset="a"), win(0, 8, asset="b")], 1, SHA))
        self.assertIsNone(tie_sensitivity(queue, 1, {i.incident_id: set() for i in queue}, {"A"}))


class PooledRecallTest(unittest.TestCase):
    def test_pooled_hits_reads_matching_per_day(self):
        days = {"d1": {"denominator": ["A", "B"], "recall": {"10": {"matching": {"A": "i1"}}}},
                "d2": {"denominator": ["C"], "recall": {10: {"matching": {"C": "i9"}}}}}
        self.assertEqual(pooled_hits(days, 10), {"A": 1, "B": 0, "C": 1})

    def test_bootstrap_is_seeded_and_brackets_point(self):
        ci = bootstrap_recall_ci([1] * 8 + [0] * 8)
        self.assertEqual(ci, bootstrap_recall_ci([1] * 8 + [0] * 8))
        self.assertEqual(ci["recall"], 0.5)
        self.assertLess(ci["low"], 0.5)
        self.assertGreater(ci["high"], 0.5)

    def test_all_hits_has_degenerate_interval(self):
        ci = bootstrap_recall_ci([1, 1, 1])
        self.assertEqual((ci["low"], ci["high"]), (1.0, 1.0))


if __name__ == "__main__":
    unittest.main()
