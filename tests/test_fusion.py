import unittest

from zeek_ad.evaluation import build_incidents, rank_queue
from zeek_ad.fusion import fuse, fuse_merge_overlaps, fuse_round_robin, picked_score

# 규칙 확인용 가짜 예제다. 실제 점수가 아니다.
SHA = {"cap": "0" * 64}


def queue(*items):
    """(자산, 시작 분, 점수) 목록 → 사건 큐. 창 하나짜리 사건들이다."""
    ws = [{"capture_id": "cap", "asset_id": a, "role": "originator", "window_start": m * 60, "score": s}
          for a, m, s in items]
    return rank_queue(build_incidents(ws, 0, SHA))


class RoundRobinTest(unittest.TestCase):
    def test_example_from_explanation(self):
        # 설명 예시: TGN [A, B, C], 꼬리 [D, E, F], Transformer [A, G, H] → A, D, B, E, G, C, F, H
        tgn = queue(("A", 0, 9), ("B", 0, 8), ("C", 0, 7))
        tail = queue(("D", 0, 9), ("E", 0, 8), ("F", 0, 7))
        tf = queue(("A", 0, 50), ("G", 0, 40), ("H", 0, 30))
        fused, sources = fuse_round_robin([tgn, tail, tf], ["tgn", "tail", "tf"])
        self.assertEqual([i.asset_id for i in fused], ["A", "D", "B", "E", "G", "C", "F", "H"])
        self.assertEqual(sources[fused[0].incident_id], ["tgn", "tf"])  # Transformer 1위는 겹쳐서 건너뜀
        self.assertEqual([i.score for i in fused[:3]], [-1.0, -2.0, -3.0])

    def test_overlap_needs_shared_window(self):
        # 같은 자산이라도 창이 겹치지 않으면 다른 사건이다.
        a = queue(("X", 0, 9))
        b = queue(("X", 60, 9))
        fused, _ = fuse_round_robin([a, b], ["a", "b"])
        self.assertEqual(len(fused), 2)

    def test_exhausted_queue_lets_others_continue(self):
        fused, _ = fuse_round_robin([queue(("A", 0, 9)), queue(("B", 0, 9), ("C", 0, 8), ("D", 0, 7))], ["a", "b"])
        self.assertEqual([i.asset_id for i in fused], ["A", "B", "C", "D"])


def runs(*items):
    """(자산, [5분 창 번호...], 점수) 목록 → 사건 큐. 이어진 창 번호는 한 사건이 된다."""
    ws = [{"capture_id": "cap", "asset_id": a, "role": "originator", "window_start": k * 300, "score": s}
          for a, ks, s in items for k in ks]
    return rank_queue(build_incidents(ws, 0, SHA))


class MergeOverlapsTest(unittest.TestCase):
    """v2(DD-018): 겹친 사건을 합치고 범위는 모델 창의 합이다."""

    def test_lab_run1_kali_case(self):
        # 실행 1: TGN은 -sV 창(11)만, 꼬리·Transformer는 -sT·-sV 창(10·11)을 꼽았다
        tgn, tail, tf = runs(("K", [11], 9)), runs(("K", [10, 11], 7)), runs(("K", [10, 11], 16))
        v1, _ = fuse_round_robin([tgn, tail, tf], ["tgn", "tail", "tf"])
        self.assertEqual(v1[0].windows, (3300,))                          # v1: TGN 창만 남았다
        v2, src = fuse_merge_overlaps([tgn, tail, tf], ["tgn", "tail", "tf"])
        self.assertEqual(len(v2), 1)
        self.assertEqual((v2[0].windows, v2[0].first_start, v2[0].last_end), ((3000, 3300), 3000, 3600))
        self.assertEqual(v2[0].incident_id, "cap|K|originator|3000")       # 첫 창 기준으로 다시 만든 ID
        self.assertEqual(src[v2[0].incident_id], ["tgn", "tail", "tf"])

    def test_id_does_not_depend_on_model_order(self):
        qs = {"tgn": runs(("K", [11], 9)), "tail": runs(("K", [10, 11], 7)), "tf": runs(("K", [10, 11], 16))}
        ids = set()
        for order in (["tgn", "tail", "tf"], ["tail", "tf", "tgn"], ["tf", "tgn", "tail"]):
            fused, _ = fuse_merge_overlaps([qs[n] for n in order], order)
            ids.add(fused[0].incident_id)
        self.assertEqual(ids, {"cap|K|originator|3000"})

    def test_bridge_merges_earlier_incidents(self):
        # TGN이 K의 창 0, 꼬리가 K의 창 2를 따로 뽑은 뒤 Transformer 사건(창 0~2)이 둘을 잇는다 → 하나, 순위는 앞 자리
        tgn = runs(("K", [0], 9), ("Z", [5], 1))
        tail = runs(("K", [2], 9))
        tf = runs(("K", [0, 1, 2], 9))
        fused, src = fuse_merge_overlaps([tgn, tail, tf], ["tgn", "tail", "tf"])
        self.assertEqual([(i.asset_id, i.windows) for i in fused], [("K", (0, 300, 600)), ("Z", (1500,))])
        self.assertEqual([i.score for i in fused], [-1.0, -2.0])
        self.assertEqual(src["cap|K|originator|0"], ["tgn", "tail", "tf"])

    def test_no_shared_window_stays_apart_and_skip_policy_is_v1(self):
        a, b = runs(("X", [0], 9)), runs(("X", [1], 9))                   # 이어져 있어도 창을 공유하지 않으면 따로
        self.assertEqual(len(fuse_merge_overlaps([a, b], ["a", "b"])[0]), 2)
        tgn, tail = runs(("K", [11], 9), ("Y", [3], 5)), runs(("K", [10, 11], 7))
        self.assertEqual(fuse([tgn, tail], ["tgn", "tail"], "skip"), fuse_round_robin([tgn, tail], ["tgn", "tail"]))
        with self.assertRaises(ValueError):
            fuse([tgn, tail], ["tgn", "tail"], "union")

    def test_picked_score(self):
        tgn, tail = runs(("K", [11], 9.5)), runs(("K", [10, 11], 7))
        v1, s1 = fuse_round_robin([tgn, tail], ["tgn", "tail"])
        self.assertEqual(picked_score(tgn, v1[0]), 9.5)                   # v1: 뽑은 사건 점수 그대로
        # v2: 뽑은 모델(TGN) 사건이 합친 범위 안에 둘(창 0, 창 2)이면 최댓값
        tgn2, tf = runs(("K", [0], 4), ("K", [2], 6)), runs(("K", [0, 1, 2], 9))
        v2, s2 = fuse_merge_overlaps([tgn2, tf], ["tgn", "tf"])
        self.assertEqual((len(v2), s2[v2[0].incident_id][0], picked_score(tgn2, v2[0])), (1, "tgn", 6))


if __name__ == "__main__":
    unittest.main()
