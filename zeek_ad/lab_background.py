"""실습망 시험의 정상 배경 트래픽(DD-017). CIC 월요일 보류 구간 재생(A)의 주소 바꾸기와 PCAP 읽기·쓰기.

A는 CIC 월요일 보류 구간을 잘라낸 PCAP이다. 내부 주소(192.168.10.x)를 실습망 예약 대역(10.10.0.100번대)으로
하나씩 바꾸고, MAC은 가짜(로컬 관리 주소)로 바꾼다. IPv4가 아닌 프레임은 뺀다(실습망 자산 설정은 IPv4 대역만 있다).
체크섬은 원래 값에서 바뀐 주소만큼만 고친다(RFC 1624 증분 갱신). 원래 체크섬이 틀렸으면 틀린 채로 남는다.
실습망 Zeek는 -C(체크섬 검사 생략)로 돌기 때문에 결과에는 영향이 없다.
표준 라이브러리만 쓴다.
"""

from ipaddress import IPv4Address, IPv4Network
import struct

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
              b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
LINKTYPE_ETHERNET = 1
ETH_IPV4 = 0x0800
# 재생할 때 실습용 카드 MTU를 9000으로 잠시 올린다(이더넷 머리 14 더함). CIC는 큰 프레임(합쳐진 TCP 조각, 최대 8,754바이트)을
# 그대로 캡처했다. 빼면 연결이 끊기고, 쪼개면 모델이 월요일에 본 패킷 수가 달라진다. 그래서 그대로 보낸다.
MAX_FRAME = 9014
FAKE_SMAC = bytes.fromhex("020000000101")
FAKE_DMAC = bytes.fromhex("020000000102")


def read_pcap(path):
    """고전 PCAP 파일의 (시각 초, 프레임) 목록을 차례로 돌려준다. 이더넷 링크만 받는다."""
    with open(path, "rb") as f:
        header = f.read(24)
        if header[:4] not in PCAP_MAGIC:
            raise ValueError(f"고전 PCAP이 아니다: {path}")
        endian, unit = PCAP_MAGIC[header[:4]]
        link = struct.unpack(endian + "I", header[20:24])[0]
        if link != LINKTYPE_ETHERNET:
            raise ValueError(f"이더넷 링크가 아니다(link type {link}): {path}")
        record = struct.Struct(endian + "IIII")
        while True:
            head = f.read(16)
            if len(head) < 16:
                return
            sec, frac, caplen, _ = record.unpack(head)
            yield sec + frac * unit, f.read(caplen)


def write_pcap(path, packets):
    """(시각 초, 프레임) 목록을 마이크로초 PCAP으로 쓴다. 반환: 쓴 패킷 수."""
    n = 0
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec == 1_000_000:
                sec, usec = sec + 1, 0
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
            n += 1
    return n


def address_map(hosts, source_net, target_net, first_host):
    """원래 내부 주소 → 실습망 주소. 호스트 주소는 정렬 순서대로 target_net의 first_host번부터 하나씩 준다.

    네트워크·방송 주소는 실습망의 네트워크·방송 주소로 바꾼다(점수 대상에서 빠지는 규칙이 그대로 이어지게).
    """
    source, target = IPv4Network(source_net), IPv4Network(target_net)
    mapping = {source.network_address: target.network_address, source.broadcast_address: target.broadcast_address}
    plain = sorted(h for h in map(IPv4Address, hosts) if h in source and h not in mapping)
    last = int(target.broadcast_address) - 1
    if int(target.network_address) + first_host + len(plain) - 1 > last:
        raise ValueError(f"실습망 대역에 주소가 모자란다: 호스트 {len(plain)}개")
    for k, h in enumerate(plain):
        mapping[h] = IPv4Address(int(target.network_address) + first_host + k)
    return {str(a): str(b) for a, b in mapping.items()}


def _csum_replace(csum, old, new):
    """16비트 체크섬에서 old 바이트를 new로 바꾼 만큼 고친다(RFC 1624: HC' = ~(~HC + ~m + m'))."""
    total = ~csum & 0xFFFF
    for k in range(0, len(old), 2):
        m, m2 = int.from_bytes(old[k:k + 2], "big"), int.from_bytes(new[k:k + 2], "big")
        total += (~m & 0xFFFF) + m2
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def rewrite_frame(frame, mapping, max_frame=MAX_FRAME):
    """IPv4 프레임의 주소·MAC을 바꾼다. 반환: 바꾼 프레임, 또는 뺄 프레임이면 None과 이유.

    VLAN 태그·IPv6·ARP 등 IPv4가 아닌 프레임과 max_frame을 넘는 프레임은 뺀다.
    """
    if len(frame) > max_frame:
        return None, "too_long"
    if len(frame) < 34 or int.from_bytes(frame[12:14], "big") != ETH_IPV4:
        return None, "not_ipv4"
    ihl = (frame[14] & 0x0F) * 4
    src, dst = frame[26:30], frame[30:34]
    new_src = IPv4Address(mapping.get(str(IPv4Address(src)), str(IPv4Address(src)))).packed
    new_dst = IPv4Address(mapping.get(str(IPv4Address(dst)), str(IPv4Address(dst)))).packed
    out = bytearray(FAKE_DMAC + FAKE_SMAC + frame[12:])
    if (new_src, new_dst) != (src, dst):
        old, new = src + dst, new_src + new_dst
        out[26:34] = new
        ip_csum = int.from_bytes(frame[24:26], "big")
        out[24:26] = _csum_replace(ip_csum, old, new).to_bytes(2, "big")
        proto, frag = frame[23], int.from_bytes(frame[20:22], "big") & 0x1FFF
        l4 = 14 + ihl
        # TCP·UDP 체크섬은 가짜 머리(주소 포함)를 덮는다. 조각의 첫 부분에만 머리가 있다
        offset = {6: 16, 17: 6}.get(proto)
        if offset is not None and frag == 0 and len(frame) >= l4 + offset + 2:
            c = int.from_bytes(frame[l4 + offset:l4 + offset + 2], "big")
            if not (proto == 17 and c == 0):              # UDP 체크섬 0은 "없음"이라 그대로 둔다
                out[l4 + offset:l4 + offset + 2] = _csum_replace(c, old, new).to_bytes(2, "big")
    return bytes(out), None


def ipv4_hosts(packets, network):
    """프레임들에 나온 IPv4 주소 중 network 안의 것. 반환: 주소 문자열 집합."""
    net, found = IPv4Network(network), set()
    for _, frame in packets:
        if len(frame) >= 34 and int.from_bytes(frame[12:14], "big") == ETH_IPV4:
            for raw in (frame[26:30], frame[30:34]):
                a = IPv4Address(raw)
                if a in net:
                    found.add(str(a))
    return found
