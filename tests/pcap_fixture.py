"""파이프라인 시험용 작은 PCAP을 표준 라이브러리로 만든다(DD-012). 운영 입력이 아니다.

이 PC의 일반 계정은 패킷 캡처 권한(CAP_NET_RAW)이 없어서, 실습망을 흉내 낸 패킷을 직접 만든다.
- TCP: 3-way handshake → HTTP 요청·응답 → FIN 종료(Zeek conn_state SF가 되도록).
- UDP: DNS 질의·응답.
- (선택) 포트 스캔: 공격자가 SYN을 보내고 대상이 RST로 거부한다(Zeek conn_state REJ). Kali nmap -sS를 흉내 낸다.
체크섬은 0으로 둔다. Zeek를 -C(체크섬 검사 생략)로 돌리므로 문제없다.
예: python tests/pcap_fixture.py out.pcap --start 2026-12-01T01:00:00Z
"""

import argparse
from datetime import datetime
import struct

LINKTYPE_ETHERNET = 1


def _mac(n):
    return bytes([0x02, 0, 0, 0, 0, n & 0xFF])


def _ip(text):
    return bytes(int(x) for x in text.split("."))


def _ipv4(src, dst, proto, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0, _ip(src), _ip(dst))
    return header + payload


def _eth(src_n, dst_n, ip_packet):
    return _mac(dst_n) + _mac(src_n) + b"\x08\x00" + ip_packet


def tcp(src, sport, dst, dport, seq, ack, flags, data=b""):
    """flags: 'S','SA','A','PA','FA' 같은 문자열."""
    bits = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10}
    f = sum(bits[c] for c in flags)
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, f, 65535, 0, 0)
    return _eth(int(src.split(".")[-1]), int(dst.split(".")[-1]), _ipv4(src, dst, 6, header + data))


def udp(src, sport, dst, dport, data):
    header = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)
    return _eth(int(src.split(".")[-1]), int(dst.split(".")[-1]), _ipv4(src, dst, 17, header + data))


def dns_query(qid, name, response=False):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    question = labels + struct.pack("!HH", 1, 1)
    if not response:
        return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([10, 10, 0, 80])
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + question + answer


def http_session(t, client, server, sport):
    """HTTP 연결 하나의 패킷 목록 [(시각, 바이트)]."""
    req = b"GET /index.html HTTP/1.1\r\nHost: intranet.lab\r\nUser-Agent: fixture\r\n\r\n"
    body = b"<html>ok</html>"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/html\r\n\r\n" % len(body) + body
    c, s = 1000, 5000
    return [
        (t + 0.000, tcp(client, sport, server, 80, c, 0, "S")),
        (t + 0.001, tcp(server, 80, client, sport, s, c + 1, "SA")),
        (t + 0.002, tcp(client, sport, server, 80, c + 1, s + 1, "A")),
        (t + 0.003, tcp(client, sport, server, 80, c + 1, s + 1, "PA", req)),
        (t + 0.010, tcp(server, 80, client, sport, s + 1, c + 1 + len(req), "PA", resp)),
        (t + 0.011, tcp(client, sport, server, 80, c + 1 + len(req), s + 1 + len(resp), "FA")),
        (t + 0.012, tcp(server, 80, client, sport, s + 1 + len(resp), c + 2 + len(req), "FA")),
        (t + 0.013, tcp(client, sport, server, 80, c + 2 + len(req), s + 2 + len(resp), "A")),
    ]


def dns_session(t, client, server, sport, qid, name):
    return [(t, udp(client, sport, server, 53, dns_query(qid, name))),
            (t + 0.002, udp(server, 53, client, sport, dns_query(qid, name, response=True)))]


def write_pcap(path, packets):
    packets = sorted(packets, key=lambda p: p[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, data in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)


def lab_traffic(start_epoch, seconds=120, clients=("10.10.0.11", "10.10.0.12"), server="10.10.0.80",
                dns="10.10.0.53"):
    """평범한 실습망 트래픽: 클라이언트마다 10초 간격으로 DNS 질의 1개와 HTTP 연결 1개."""
    packets = []
    port = 40000
    for k, t in enumerate(range(0, seconds, 10)):
        for client in clients:
            port += 1
            packets += dns_session(start_epoch + t, client, dns, port, (k * 7 + port) & 0xFFFF, "intranet.lab")
            port += 1
            packets += http_session(start_epoch + t + 0.5, client, server, port)
    return packets


def port_scan(start_epoch, attacker, target, ports, seconds=60):
    """닫힌 포트 스캔: 포트마다 SYN → RST·ACK. ports개 포트를 seconds초 동안 고르게 훑는다."""
    packets = []
    for k in range(ports):
        t = start_epoch + seconds * k / ports
        sport, dport = 50000 + (k % 10000), 1 + k
        packets.append((t, tcp(attacker, sport, target, dport, 7000 + k, 0, "S")))
        packets.append((t + 0.0005, tcp(target, dport, attacker, sport, 0, 7001 + k, "RA")))
    return packets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out")
    parser.add_argument("--start", required=True, help="첫 패킷 시각(UTC ISO)")
    parser.add_argument("--seconds", type=int, default=120)
    parser.add_argument("--scan", nargs=3, metavar=("ATTACKER", "TARGET", "PORTS"),
                        help="포트 스캔을 섞는다. 예: --scan 10.10.0.66 10.10.0.80 1000 (시작 30초 뒤부터 60초 동안)")
    args = parser.parse_args()
    start = datetime.fromisoformat(args.start.replace("Z", "+00:00")).timestamp()
    packets = lab_traffic(start, args.seconds)
    if args.scan:
        packets += port_scan(start + 30, args.scan[0], args.scan[1], int(args.scan[2]))
    write_pcap(args.out, packets)


if __name__ == "__main__":
    main()
