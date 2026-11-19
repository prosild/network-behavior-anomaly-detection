import unittest

from zeek_ad.tgn_data import (
    NONE, UNKNOWN, build_vocab, direction, encode, encode_history, entropy, http_status_class, ip_hash_features,
    port_group, ssl_state,
)

# 규칙 확인용 가짜 예제다. 실제 CIC 값이 아니다.


class CategoryTest(unittest.TestCase):
    def test_vocab_reserves_none_and_unknown(self):
        vocab = build_vocab(["b", "a", "a", "b", "c", None], min_count=2)
        self.assertEqual(vocab, {"a": 2, "b": 3})
        self.assertEqual([encode(None, vocab), encode("c", vocab), encode("a", vocab)], [NONE, UNKNOWN, 2])

    def test_small_rules(self):
        self.assertEqual(port_group("tcp", 445), "tcp:smb")
        self.assertEqual(port_group("tcp", 40000), "tcp:high")
        self.assertEqual(direction(True, False), "in-out")
        self.assertEqual(http_status_class(404), "4xx")
        self.assertIsNone(http_status_class(None))
        self.assertEqual(ssl_state("TLSv12", True, "a.com", False), "est:sni:mismatch")
        self.assertEqual(ssl_state("TLSv12", False, None, None), "noest:nosni")
        self.assertIsNone(ssl_state(None, None, None, None))

    def test_history_padding_and_unknown(self):
        self.assertEqual(encode_history("Sh", 4)[2:], [0, 0])
        self.assertEqual(encode_history("S?", 3)[1], UNKNOWN)
        self.assertEqual(len(encode_history("ShADadfFShADadfF", 12)), 12)


class NumericTest(unittest.TestCase):
    def test_entropy(self):
        self.assertEqual(entropy(""), 0.0)
        self.assertEqual(entropy("aaaa"), 0.0)
        self.assertAlmostEqual(entropy("ab"), 1.0)


class IpHashTest(unittest.TestCase):
    def test_same_block_shares_prefix_terms(self):
        a, b, c = (ip_hash_features(x, 16) for x in ("8.8.4.4", "8.8.4.5", "200.1.2.3"))
        dot = lambda u, v: sum(x * y for x, y in zip(u, v))  # noqa: E731
        self.assertGreater(dot(a, b), dot(a, c))
        self.assertEqual(a, ip_hash_features("8.8.4.4", 16))  # 실행마다 같다(파이썬 hash()를 쓰지 않는다)

    def test_ipv6(self):
        self.assertEqual(len(ip_hash_features("2001:db8::1", 16)), 16)


if __name__ == "__main__":
    unittest.main()
