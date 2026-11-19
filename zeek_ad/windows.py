"""시각을 고정 창에 배정하고, 창을 학습/보류 구간으로 나눈다."""

import json
import math
from pathlib import Path


PROJECT_CONFIG = (
    Path(__file__).resolve().parents[1] / "configs" / "time-windows.v1.json"
)


def load_window_config(config_path):
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    if not (isinstance(config["window_seconds"], int) and config["window_seconds"] > 0):
        raise ValueError("window_seconds must be a positive integer")
    if not 0 < config["split_fraction"] < 1:
        raise ValueError("split_fraction must be between 0 and 1")
    return config


def window_start(ts, window_seconds):
    # 캡처 시작이 아니라 Unix epoch에 맞춘다. 창은 [start, end) 반열린 구간이다.
    return math.floor(ts / window_seconds) * window_seconds


def fraction_cutoff(capture_min, capture_max, fraction):
    """끝난 캡처에서 쓰는 오프라인 규칙. 실시간 운영은 cutoff를 직접 넘긴다."""
    return capture_min + fraction * (capture_max - capture_min)


def is_capture_edge(start, window_seconds, capture_min, capture_max):
    # 캡처가 창 전체를 덮지 못하면 불완전한 창이다.
    return start < capture_min or start + window_seconds > capture_max


def assign_split(start, window_seconds, capture_min, capture_max, cutoff):
    end = start + window_seconds
    if is_capture_edge(start, window_seconds, capture_min, capture_max):
        return "capture_edge"
    if end <= cutoff:
        return "train"
    if start >= cutoff:
        return "holdout"
    # start < cutoff < end: cutoff 앞뒤 데이터가 섞인 창이라 학습·보류 어디에도 넣지 않는다.
    return "split_boundary"


def label_window(start, window_seconds, capture_min, capture_max, usage, split_fraction):
    """캡처 용도에 따라 창 라벨을 정한다.

    학습 캡처(train_holdout)만 cutoff로 나눈다. 다른 캡처의 완전한 창은 용도 이름을 그대로 쓴다.
    """
    if usage == "train_holdout":
        cutoff = fraction_cutoff(capture_min, capture_max, split_fraction)
        return assign_split(start, window_seconds, capture_min, capture_max, cutoff)
    if is_capture_edge(start, window_seconds, capture_min, capture_max):
        return "capture_edge"
    return usage
