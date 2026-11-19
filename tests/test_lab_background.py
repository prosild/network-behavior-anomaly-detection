"""실습망 배경 트래픽(zeek_ad.lab_background, DD-017) 시험. 표준 라이브러리만 쓴다.

실행: python -m unittest tests.test_lab_background -v
"""

from pathlib import Path
import struct
import tempfile
import unittest

from zeek_ad.lab_background import FAKE_DMAC, FAKE_SMAC, address_map, read_pcap, rewrite_frame, write_pcap


def checksum(data):
    """인터넷 체크섬(시험용 전체 계산)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(src, dst, proto, l4, frag=0):
    """체크섬이 맞는 이더넷 + IPv4 + (TCP·UDP) 프레임."""
    s, d = bytes(map(int, src.split("."))), bytes(map(int, dst.split(".")))
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, frag, 64, proto, 0, s, d))
    ip[10:12] = checksum(bytes(ip)).to_bytes(2, "big")
    l4 = bytearray(l4)
    off = {6: 16, 17: 6}[proto]
    if not (proto == 17 and l4[off:off + 2] == b"\x00\x00"):
        l4[off:off + 2] = b"\x00\x00"
        pseudo = s + d + struct.pack("!BBH", 0, proto, len(l4))
        l4[off:off + 2] = checksum(pseudo + bytes(l4)).to_bytes(2, "big")
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + bytes(ip) + bytes(l4)


def tcp_segment(payload=b"hello"):
    return struct.pack("!HHIIBBHHH", 50000, 80, 1, 0, 5 << 4, 0x18, 1024, 0, 0) + payload


def valid(f):
    """IP·TCP/UDP 체크섬이 맞는가."""
    ip = f[14:34]
    proto, s, d, l4 = f[23], f[26:30], f[30:34], f[34:]
    pseudo = s + d + struct.pack("!BBH", 0, proto, len(l4))
    return checksum(ip) == 0 and checksum(pseudo + l4) == 0


class AddressMapTest(unittest.TestCase):
    def test_hosts_in_order_and_edges(self):
        m = address_map({"192.168.10.50", "192.168.10.3", "192.168.10.255", "8.8.8.8"},
                        "192.168.10.0/24", "10.10.0.0/24", 100)
        self.assertEqual(m["192.168.10.3"], "10.10.0.100")          # 숫자 순서(.3이 .50보다 먼저)
        self.assertEqual(m["192.168.10.50"], "10.10.0.101")
        self.assertEqual(m["192.168.10.255"], "10.10.0.255")        # 방송 주소는 방송 주소로(점수 대상 아님 유지)
        self.assertNotIn("8.8.8.8", m)                              # 외부 주소는 그대로

    def test_overflow(self):
        hosts = {f"192.168.10.{k}" for k in range(1, 200)}
        with self.assertRaises(ValueError):
            address_map(hosts, "192.168.10.0/24", "10.10.0.0/24", 100)


class RewriteTest(unittest.TestCase):
    MAP = {"192.168.10.3": "10.10.0.100", "192.168.10.50": "10.10.0.101"}

    def test_tcp_checksums_stay_valid(self):
        f = frame("192.168.10.3", "93.184.216.34", 6, tcp_segment())
        self.assertTrue(valid(f))
        new, reason = rewrite_frame(f, self.MAP)
        self.assertIsNone(reason)
        self.assertEqual((new[26:30], new[30:34]), (bytes([10, 10, 0, 100]), bytes([93, 184, 216, 34])))
        self.assertEqual(new[:12], FAKE_DMAC + FAKE_SMAC)
        self.assertTrue(valid(new))                                 # 증분 갱신 뒤에도 맞다
        self.assertEqual(new[34:50] + new[52:], f[34:50] + f[52:])  # 체크섬 칸 말고 내용(포트·데이터)은 그대로

    def test_udp_both_ends_and_zero_checksum(self):
        udp = struct.pack("!HHHH", 5353, 53, 12, 0) + b"abcd"
        f = frame("192.168.10.50", "192.168.10.3", 17, udp)        # UDP 체크섬 0(없음)
        new, _ = rewrite_frame(f, self.MAP)
        self.assertEqual(new[40:42], b"\x00\x00")                   # 없음은 그대로 둔다
        self.assertEqual(checksum(new[14:34]), 0)
        self.assertEqual((new[26:30], new[30:34]), (bytes([10, 10, 0, 101]), bytes([10, 10, 0, 100])))

    def test_dropped_frames(self):
        arp = b"\xff" * 6 + b"\xbb" * 6 + b"\x08\x06" + b"\x00" * 28
        self.assertEqual(rewrite_frame(arp, self.MAP), (None, "not_ipv4"))
        big = frame("192.168.10.3", "1.1.1.1", 6, tcp_segment(b"x" * 9000))
        self.assertEqual(rewrite_frame(big, self.MAP), (None, "too_long"))
        jumbo = frame("192.168.10.3", "1.1.1.1", 6, tcp_segment(b"x" * 8000))   # CIC의 큰 프레임은 그대로 보낸다
        self.assertTrue(valid(rewrite_frame(jumbo, self.MAP)[0]))

    def test_pcap_roundtrip(self):
        packets = [(1499000000.25, frame("192.168.10.3", "1.1.1.1", 6, tcp_segment())),
                   (1499000001.999999, frame("192.168.10.50", "1.1.1.1", 6, tcp_segment()))]
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.pcap"
            self.assertEqual(write_pcap(p, packets), 2)
            back = list(read_pcap(p))
        self.assertEqual([f for _, f in back], [f for _, f in packets])
        self.assertAlmostEqual(back[1][0], packets[1][0], places=5)


if __name__ == "__main__":
    unittest.main()
