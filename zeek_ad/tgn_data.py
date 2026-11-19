"""TGN 학습 데이터 인코딩 규칙(DD-007). 표준 라이브러리만 쓴다.

- 범주 어휘는 월요일 train에서만 만든다. 0 = 값 없음, 1 = 모름.
- IP 노드 특징은 주소 문자열만으로 만든다(데이터를 보지 않는다). 그래서 처음 보는 IP도 같은 방식으로 표현된다.
"""

from collections import Counter
import hashlib
import ipaddress
import math

NONE, UNKNOWN = 0, 1

# 받는 쪽 포트를 서비스군으로 묶는다. 나머지는 1024 미만이면 포트 그대로, 이상이면 high.
PORT_GROUPS = {
    22: "ssh", 23: "telnet", 135: "rpc", 139: "smb", 445: "smb", 3389: "rdp", 5985: "winrm", 5986: "winrm",
    53: "dns", 80: "web", 443: "web", 8080: "web", 8443: "web",
    88: "auth", 389: "auth", 464: "auth", 636: "auth", 3268: "auth", 3269: "auth",
    123: "ntp", 137: "netbios", 138: "netbios", 21: "ftp", 25: "mail", 465: "mail", 587: "mail",
}
HISTORY_CHARS = "ShADadFfRrCcGgIiJjQqTtWw^"


def port_group(proto, port):
    if proto not in ("tcp", "udp"):
        return proto  # icmp 등의 포트 칸은 유형·코드라 포트군으로 보지 않는다
    if port is None:
        return f"{proto}:none"
    port = int(port)
    if port in PORT_GROUPS:
        return f"{proto}:{PORT_GROUPS[port]}"
    return f"{proto}:{port}" if port < 1024 else f"{proto}:high"


def direction(orig_internal, resp_internal):
    return {(True, True): "in-in", (True, False): "in-out", (False, True): "out-in", (False, False): "out-out"}[
        (bool(orig_internal), bool(resp_internal))]


def http_status_class(status):
    if status is None:
        return None
    return f"{int(status) // 100}xx"


def ssl_state(version, established, sni, sni_matches_cert):
    """SSL 연결 상태를 범주 하나로 묶는다. SSL 기록이 없으면 None."""
    if version is None and established is None:
        return None
    est = "est" if established else "noest"
    if not sni:
        return f"{est}:nosni"
    match = {True: "match", False: "mismatch"}.get(sni_matches_cert, "unknown")
    return f"{est}:sni:{match}"


def ssh_auth(success):
    return None if success is None else ("ok" if success else "fail")


def entropy(text):
    """문자 단위 Shannon 엔트로피(bit). 빈 값은 0."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def build_vocab(values, min_count):
    """train 값 목록으로 어휘를 만든다. None은 세지 않는다. 번호는 2부터, 정렬 순서로 고정한다."""
    counts = Counter(v for v in values if v is not None)
    kept = sorted(v for v, c in counts.items() if c >= min_count)
    return {v: i + 2 for i, v in enumerate(kept)}


def encode(value, vocab):
    if value is None:
        return NONE
    return vocab.get(value, UNKNOWN)


def encode_history(history, max_len):
    """TCP history 문자열을 문자 번호 목록으로. 0 = 패딩, 1 = 모르는 문자, 앞에서 max_len자까지."""
    ids = [HISTORY_CHARS.find(ch) + 2 if ch in HISTORY_CHARS else UNKNOWN for ch in (history or "")[:max_len]]
    return ids + [0] * (max_len - len(ids))


def ip_hash_features(address, dim):
    """옥텟 계층 접두사(a, a.b, a.b.c, a.b.c.d)마다 sha256 부호 해시를 더한 벡터.

    같은 대역의 IP는 앞쪽 접두사를 공유해 벡터가 비슷해진다. IPv6는 16비트 묶음 4개까지 쓴다.
    """
    ip = ipaddress.ip_address(address)
    parts = address.split(".") if ip.version == 4 else ip.exploded.split(":")[:4]
    sep = "." if ip.version == 4 else ":"
    vec = [0.0] * dim
    for k in range(1, len(parts) + 1):
        digest = hashlib.sha256(sep.join(parts[:k]).encode()).digest()
        idx = int.from_bytes(digest[:4], "big") % dim
        vec[idx] += 1.0 if digest[4] & 1 else -1.0
    return vec


def ip_flags(address, networks, is_scored):
    ip = ipaddress.ip_address(address)
    internal = any(ip in n for n in networks)
    return [float(internal), float(is_scored), float(ip.is_private), float(ip.version == 6)]
