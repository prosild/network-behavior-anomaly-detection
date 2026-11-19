"""정답 공격 에피소드의 기록 형식과 Recall 분모 계산."""

from collections import Counter
from dataclasses import dataclass

from zeek_ad.assets import ROLES


STATUSES = ("confirmed", "uncertain", "unsupported")


@dataclass(frozen=True)
class Observation:
    """에피소드의 하위 관측. 한 캡처에서 한 자산·역할이 관여한 시간 범위."""

    capture_id: str
    asset_id: str
    role: str
    start: float  # UTC epoch 초
    end: float

    def __post_init__(self):
        if self.role not in ROLES:
            raise ValueError(f"unknown role: {self.role}")
        if not self.start < self.end:
            raise ValueError("start must be earlier than end")


@dataclass(frozen=True)
class Episode:
    episode_id: str
    scenario: str
    status: str
    status_reason: str  # uncertain·unsupported도 판단 이유를 남긴다
    observations: tuple

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"unknown status: {self.status}")
        if not self.status_reason.strip():
            raise ValueError("status_reason is required")
        if not self.observations:
            raise ValueError("an episode needs at least one observation")


def _require_unique_ids(episodes):
    # 집합으로 세기 때문에 ID가 겹치면 서로 다른 에피소드가 조용히 하나로 합쳐진다.
    duplicates = [i for i, n in Counter(ep.episode_id for ep in episodes).items() if n > 1]
    if duplicates:
        raise ValueError(f"duplicate episode_id: {sorted(duplicates)}")


def daily_denominator(episodes, capture_id):
    """그 캡처에 관측이 있는 confirmed 에피소드 ID. 자산·역할이 여러 개여도 한 번만 센다."""
    _require_unique_ids(episodes)
    return {
        ep.episode_id for ep in episodes
        if ep.status == "confirmed"
        and any(obs.capture_id == capture_id for obs in ep.observations)
    }


def unique_confirmed(episodes):
    """전체 기간의 고유 confirmed 에피소드 ID. 일별 분모의 합과 다를 수 있다."""
    _require_unique_ids(episodes)
    return {ep.episode_id for ep in episodes if ep.status == "confirmed"}


def status_counts(episodes):
    """분모에서 빠진 uncertain·unsupported도 함께 보고하기 위한 상태별 개수."""
    _require_unique_ids(episodes)
    return Counter(ep.status for ep in episodes)
