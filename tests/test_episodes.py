import unittest

from zeek_ad.episodes import (
    Episode, Observation, daily_denominator, status_counts, unique_confirmed,
)


# 규칙 확인용 가짜 예제다. 실제 CIC 정답 사건표가 아니다.
def obs(capture_id, asset_id, role, start=0.0, end=60.0):
    return Observation(capture_id, asset_id, role, start, end)


SCAN = Episode(  # 한 에피소드가 여러 자산·역할에 걸친 경우
    "ep-a", "example-scan", "confirmed", "대표 구간 3개에서 근거 확인",
    (obs("cap-thu", "192.168.10.8", "originator"),
     obs("cap-thu", "192.168.10.3", "responder"),
     obs("cap-thu", "192.168.10.50", "responder")),
)
TWO_DAYS = Episode(  # 같은 공격이 두 캡처에 이어진 경우
    "ep-b", "example-bot", "confirmed", "두 캡처에서 같은 시나리오 근거 확인",
    (obs("cap-thu", "192.168.10.5", "originator"),
     obs("cap-fri", "192.168.10.5", "originator")),
)
UNCERTAIN = Episode(
    "ep-c", "example-web", "uncertain", "45분 내 근거 부족",
    (obs("cap-thu", "192.168.10.50", "responder"),),
)
UNSUPPORTED = Episode(
    "ep-d", "example-infiltration", "unsupported", "conn에서 관련 연결을 찾지 못함",
    (obs("cap-fri", "192.168.10.25", "originator"),),
)
EPISODES = [SCAN, TWO_DAYS, UNCERTAIN, UNSUPPORTED]


class DenominatorTest(unittest.TestCase):
    def test_multi_asset_episode_counts_once(self):
        self.assertEqual(daily_denominator(EPISODES, "cap-thu"), {"ep-a", "ep-b"})

    def test_multi_day_episode_counts_in_each_day_but_once_overall(self):
        self.assertEqual(daily_denominator(EPISODES, "cap-fri"), {"ep-b"})
        self.assertEqual(unique_confirmed(EPISODES), {"ep-a", "ep-b"})
        # 일별 분모의 합(2 + 1)을 독립 공격 수로 쓰면 안 된다.
        daily_sum = sum(len(daily_denominator(EPISODES, c)) for c in ["cap-thu", "cap-fri"])
        self.assertEqual(daily_sum, 3)

    def test_unconfirmed_are_reported_not_dropped(self):
        self.assertEqual(
            status_counts(EPISODES),
            {"confirmed": 2, "uncertain": 1, "unsupported": 1},
        )

    def test_duplicate_id_raises(self):
        copy = Episode("ep-a", "other", "confirmed", "이유", (obs("cap-fri", "192.168.10.9", "originator"),))
        with self.assertRaises(ValueError):
            unique_confirmed(EPISODES + [copy])


class ValidationTest(unittest.TestCase):
    def test_invalid_records_raise(self):
        one = (obs("cap-thu", "192.168.10.8", "originator"),)
        cases = [
            lambda: Episode("x", "s", "maybe", "이유", one),
            lambda: Episode("x", "s", "uncertain", " ", one),
            lambda: Episode("x", "s", "confirmed", "이유", ()),
            lambda: obs("cap-thu", "192.168.10.8", "attacker"),
            lambda: obs("cap-thu", "192.168.10.8", "originator", start=60.0, end=60.0),
        ]
        for make in cases:
            with self.assertRaises(ValueError):
                make()


if __name__ == "__main__":
    unittest.main()
