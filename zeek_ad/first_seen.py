"""first-seen 탐지기 규칙(DD-006 작업 2-1). 표준 라이브러리만 쓴다.

창(자산, 역할, 5분)에서 처음 등장한 "관계" 항목에 가중치를 매겨 더한다.
- 외부 관계: (방향, 자산, 외부 대역). IPv4는 /24, IPv6는 /64로 묶는다.
- 내부 관계: (출발 자산, 도착 자산, 프로토콜:포트군). 두 끝 자산의 창이 같은 항목을 함께 받는다.

seen-set은 월요일 train으로 시작한다. 평가 중에는 경보가 없던 항목만 지연 후에 편입한다.
공격 항목이 경보 직후 곧바로 "본 적 있음"이 되지 않게 하려는 것이다.
"""

from collections import defaultdict
import ipaddress

ORIGINATOR = "originator"

# 이름 있는 포트군. 나머지는 1024 미만이면 포트 그대로, 이상이면 high로 묶는다.
PORT_GROUPS = {
    22: "ssh", 23: "telnet", 135: "rpc", 139: "smb", 445: "smb", 3389: "rdp", 5985: "winrm", 5986: "winrm",
    53: "dns", 80: "web", 443: "web", 8080: "web", 8443: "web",
    88: "auth", 389: "auth", 464: "auth", 636: "auth", 3268: "auth", 3269: "auth",
    123: "ntp", 137: "netbios", 138: "netbios", 21: "ftp", 25: "mail", 465: "mail", 587: "mail",
}


def port_group(proto, port):
    if proto not in ("tcp", "udp"):
        return f"{proto}"  # icmp의 포트 칸은 유형·코드라 포트군으로 보지 않는다
    if port is None:
        return f"{proto}:none"
    port = int(port)
    if port in PORT_GROUPS:
        return f"{proto}:{PORT_GROUPS[port]}"
    return f"{proto}:{port}" if port < 1024 else f"{proto}:high"


def external_block(address):
    ip = ipaddress.ip_address(address)
    prefix = 24 if ip.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def relation_item(asset, role, peer, peer_is_internal, proto, resp_port, weights, remote_admin_groups):
    """역할 행 하나를 (항목, 가중치)로 바꾼다. resp_port는 연결을 받은 쪽 포트다."""
    if peer_is_internal:
        src, dst = (asset, peer) if role == ORIGINATOR else (peer, asset)
        group = port_group(proto, resp_port)
        weight = weights["internal_remote_admin"] if group in remote_admin_groups else weights["internal_pair"]
        return f"I|{src}|{dst}|{group}", weight
    direction = "out" if role == ORIGINATOR else "in"
    return f"E|{direction}|{asset}|{external_block(peer)}", weights["external_block"]


def score_static(rows, seen):
    """seen-set을 바꾸지 않고 점수를 매긴다. rows: {(키): {항목: 가중치}}. 반환: {키: (점수, 새 항목들)}."""
    out = {}
    for key, items in rows.items():
        new = {i: w for i, w in items.items() if i not in seen}
        out[key] = (sum(new.values()), set(new))
    return out


def score_streaming(rows, seen, threshold, delay_windows, window_seconds):
    """창 시각 순서로 점수를 매기며 seen-set을 갱신한다(seen은 그 자리에서 바뀐다).

    rows: {(capture_id, asset_id, role, window_start): {항목: 가중치}}. 한 캡처 안의 행만 넣는다.
    - 각 창의 점수는 그 시점의 seen-set 기준이다.
    - 그 창에서 처음 본 항목은, 그 항목을 가진 어느 행도 경보(점수 >= threshold)가 아니면
      delay_windows 창 뒤에 편입된다. 하나라도 경보면 편입하지 않는다(다음에 다시 나오면 다시 판단).
    """
    by_window = defaultdict(list)
    for key in rows:
        by_window[key[3]].append(key)
    pending = defaultdict(set)  # 편입 시각 → 항목
    out = {}
    for start in sorted(by_window):
        for due in [t for t in pending if t <= start]:
            seen |= pending.pop(due)
        alerted, quiet = set(), set()
        for key in by_window[start]:
            new = {i: w for i, w in rows[key].items() if i not in seen}
            score = sum(new.values())
            out[key] = (score, set(new))
            (alerted if score >= threshold else quiet).update(new)
        if quiet - alerted:
            pending[start + delay_windows * window_seconds] |= quiet - alerted
    return out
