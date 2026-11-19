from datetime import datetime, timezone
import unittest

from zeek_ad.windows import (
    PROJECT_CONFIG, assign_split, fraction_cutoff, label_window, load_window_config, window_start,
)


CONFIG = load_window_config(PROJECT_CONFIG)
W = CONFIG["window_seconds"]


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc).timestamp()


def mon(h, m, s=0, us=0):
    return utc(2017, 7, 3, h, m, s, us)


# 월요일 패킷 시각 최소·최대. IMPLEMENTATION_CHECKLIST.md 2.3절의 capinfos 값.
MON_MIN, MON_MAX = 1499082958.598308, 1499112094.472889


class WindowStartTest(unittest.TestCase):
    def test_start_is_inclusive_and_end_is_exclusive(self):
        self.assertEqual(window_start(mon(18, 25), W), mon(18, 25))
        self.assertEqual(window_start(mon(18, 24, 59, 999999), W), mon(18, 20))

    def test_windows_align_to_epoch_not_capture_start(self):
        self.assertEqual(window_start(MON_MIN, W), mon(11, 55))


class GenericSplitTest(unittest.TestCase):
    """가짜 캡처. 규칙이 월요일 값에 의존하지 않음을 보인다."""

    def setUp(self):
        self.lo, self.hi = utc(2020, 1, 1, 0, 3, 10), utc(2020, 1, 1, 1, 0, 0)
        self.cutoff = fraction_cutoff(self.lo, self.hi, 0.8)  # 00:48:38

    def split(self, h, m):
        return assign_split(utc(2020, 1, 1, h, m), W, self.lo, self.hi, self.cutoff)

    def test_each_category(self):
        self.assertEqual(self.split(0, 0), "capture_edge")
        self.assertEqual(self.split(0, 5), "train")
        self.assertEqual(self.split(0, 40), "train")
        self.assertEqual(self.split(0, 45), "split_boundary")
        self.assertEqual(self.split(0, 50), "holdout")
        self.assertEqual(self.split(0, 55), "holdout")  # 창 끝이 캡처 최대 시각과 같음
        self.assertEqual(self.split(1, 0), "capture_edge")

    def test_cutoff_on_window_start_leaves_no_boundary_window(self):
        # 운영처럼 cutoff를 창 경계에 맞추면 섞인 창이 없어 버리는 창도 없다.
        cutoff = utc(2020, 1, 1, 0, 45)
        args = (W, self.lo, self.hi, cutoff)
        self.assertEqual(assign_split(utc(2020, 1, 1, 0, 40), *args), "train")
        self.assertEqual(assign_split(utc(2020, 1, 1, 0, 45), *args), "holdout")


class MondayCrossCheckTest(unittest.TestCase):
    """일반 규칙으로 계산한 결과가 FINAL_PROJECT_DESIGN.md 6.1절 경계와 같아야 한다."""

    def setUp(self):
        self.cutoff = fraction_cutoff(MON_MIN, MON_MAX, CONFIG["split_fraction"])

    def split(self, h, m, window_seconds=W):
        return assign_split(mon(h, m), window_seconds, MON_MIN, MON_MAX, self.cutoff)

    def test_cutoff_matches_design(self):
        self.assertAlmostEqual(self.cutoff, mon(18, 24, 27, 297973), delta=1e-6)

    def test_boundaries_match_design(self):
        self.assertEqual(self.split(11, 55), "capture_edge")
        self.assertEqual(self.split(12, 0), "train")
        self.assertEqual(self.split(18, 15), "train")
        self.assertEqual(self.split(18, 20), "split_boundary")
        self.assertEqual(self.split(18, 25), "holdout")
        self.assertEqual(self.split(19, 55), "holdout")
        self.assertEqual(self.split(20, 0), "capture_edge")

    def test_other_window_size_uses_same_rule(self):
        # 1분 창 비교 실험이 아니다. 창 크기를 바꿔도 같은 규칙이 동작함만 확인한다.
        self.assertEqual(self.split(18, 23, 60), "train")
        self.assertEqual(self.split(18, 24, 60), "split_boundary")
        self.assertEqual(self.split(18, 25, 60), "holdout")


if __name__ == "__main__":
    unittest.main()


class LabelWindowTest(unittest.TestCase):
    """캡처 용도별 라벨. 학습 캡처는 assign_split과 같고, 다른 캡처는 cutoff로 나누지 않는다."""

    def label(self, h, m, usage):
        return label_window(mon(h, m), W, MON_MIN, MON_MAX, usage, CONFIG["split_fraction"])

    def test_train_capture_uses_split(self):
        self.assertEqual(self.label(18, 15, "train_holdout"), "train")
        self.assertEqual(self.label(18, 20, "train_holdout"), "split_boundary")
        self.assertEqual(self.label(18, 25, "train_holdout"), "holdout")

    def test_other_capture_keeps_usage_and_edges(self):
        self.assertEqual(self.label(11, 55, "retrospective_eval"), "capture_edge")
        self.assertEqual(self.label(18, 20, "retrospective_eval"), "retrospective_eval")
        self.assertEqual(self.label(20, 0, "development"), "capture_edge")
