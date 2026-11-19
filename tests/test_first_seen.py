import unittest

from zeek_ad.first_seen import external_block, port_group, relation_item, score_static, score_streaming

# 규칙 확인용 가짜 예제다. 실제 CIC 값이 아니다.
W = {"external_block": 1.0, "internal_pair": 3.0, "internal_remote_admin": 10.0}
ADMIN = {"tcp:smb", "tcp:rdp", "tcp:ssh", "tcp:rpc", "tcp:winrm"}


def key(start, asset="a", role="originator"):
    return ("cap", asset, role, start)


class RuleTest(unittest.TestCase):
    def test_port_groups(self):
        self.assertEqual(port_group("tcp", 445), "tcp:smb")
        self.assertEqual(port_group("udp", 161), "udp:161")
        self.assertEqual(port_group("tcp", 50000), "tcp:high")
        self.assertEqual(port_group("icmp", 8), "icmp")

    def test_external_blocks(self):
        self.assertEqual(external_block("8.8.4.4"), "8.8.4.0/24")
        self.assertEqual(external_block("2001:db8::1"), "2001:db8::/64")

    def test_internal_pair_direction_is_same_for_both_roles(self):
        # 같은 연결을 출발 자산·도착 자산 양쪽에서 보면 같은 항목이어야 한다.
        a = relation_item("10.0.0.1", "originator", "10.0.0.2", True, "tcp", 445, W, ADMIN)
        b = relation_item("10.0.0.2", "responder", "10.0.0.1", True, "tcp", 445, W, ADMIN)
        self.assertEqual(a, b)
        self.assertEqual(a[1], 10.0)

    def test_external_direction_differs(self):
        out = relation_item("10.0.0.1", "originator", "8.8.8.8", False, "udp", 53, W, ADMIN)
        inn = relation_item("10.0.0.1", "responder", "8.8.8.8", False, "tcp", 22, W, ADMIN)
        self.assertNotEqual(out[0], inn[0])


class ScoreTest(unittest.TestCase):
    def test_static_counts_only_unseen(self):
        out = score_static({key(0): {"x": 1.0, "y": 3.0}}, seen={"x"})
        self.assertEqual(out[key(0)], (3.0, {"y"}))

    def test_quiet_item_enters_seen_after_delay(self):
        rows = {key(0): {"x": 1.0}, key(300): {"x": 1.0}, key(600): {"x": 1.0}}
        out = score_streaming(rows, set(), threshold=5, delay_windows=2, window_seconds=300)
        # 0분에 처음 봄(경보 아님) → 10분부터 seen. 5분에는 아직 새 항목이다.
        self.assertEqual([out[key(t)][0] for t in (0, 300, 600)], [1.0, 1.0, 0.0])

    def test_alerted_item_is_not_learned(self):
        rows = {key(0): {"z": 10.0}, key(300): {"z": 10.0}, key(3000): {"z": 10.0}}
        out = score_streaming(rows, set(), threshold=5, delay_windows=1, window_seconds=300)
        self.assertEqual([out[key(t)][0] for t in (0, 300, 3000)], [10.0, 10.0, 10.0])

    def test_item_alerted_in_any_row_is_not_learned(self):
        # 내부 쌍은 두 자산의 행에 같이 나온다. 한쪽이라도 경보면 편입하지 않는다.
        rows = {key(0, "a"): {"p": 3.0, "q": 9.0}, key(0, "b", "responder"): {"p": 3.0},
                key(600, "b", "responder"): {"p": 3.0}}
        out = score_streaming(rows, set(), threshold=10, delay_windows=1, window_seconds=300)
        self.assertEqual(out[key(600, "b", "responder")][0], 3.0)


if __name__ == "__main__":
    unittest.main()
