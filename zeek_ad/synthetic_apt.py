"""합성 APT 패턴 생성(DD-008). Zeek 로그 행(dict)을 만든다. 표준 라이브러리만 쓴다.

패턴 함수는 conn 행과 그 uid에 딸린 프로토콜 로그 행(dns, ssl, kerberos, smb_mapping, smb_files, dce_rpc)을 함께 만든다.
값의 형식과 크기는 월요일 실제 로그를 본떠 정했다. 무작위성은 넘겨받은 random.Random 하나에서만 나온다.
"""

import base64
from dataclasses import dataclass, field
import hashlib
import ipaddress
import string
import struct

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}
UID_CHARS = string.ascii_letters + string.digits
BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567"


def community_id(orig_h, orig_p, resp_h, resp_p, proto, seed=0):
    """Community ID v1(tcp·udp). 두 끝점을 정렬해 sha1을 구하고 base64로 쓴다."""
    a, b = ipaddress.ip_address(orig_h).packed, ipaddress.ip_address(resp_h).packed
    if (a, orig_p) > (b, resp_p):
        a, b, orig_p, resp_p = b, a, resp_p, orig_p
    data = struct.pack("!H", seed) + a + b + struct.pack("!BBHH", PROTO_NUM[proto], 0, orig_p, resp_p)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()


def make_uid(rng):
    return "C" + "".join(rng.choice(UID_CHARS) for _ in range(17))


@dataclass
class Episode:
    """패턴 한 번의 주입 결과. logs는 로그 이름 → 행 목록, truth는 정답 창 계산용 (uid, 자산, 역할, _write_ts)."""
    pattern: str
    attacker: str
    start: float
    logs: dict = field(default_factory=dict)
    truth: list = field(default_factory=list)

    def add(self, log, row):
        self.logs.setdefault(log, []).append(row)

    @property
    def end(self):
        return max(r["_write_ts"] for r in self.logs["conn"])


class Context:
    """한 날의 주입에 필요한 공통 상태: 난수, 지연 규칙, 출발 포트, uid 중복 방지."""

    def __init__(self, rng, delays, used_uids):
        self.rng, self.delays, self.used_uids = rng, delays, used_uids
        self.next_port = {}
        self.issued = []  # 이번 시도에서 새로 쓴 uid(실패하면 되돌린다)

    def uid(self):
        while True:
            u = make_uid(self.rng)
            if u not in self.used_uids:
                self.used_uids.add(u)
                self.issued.append(u)
                return u

    def port(self, host):
        # 호스트마다 임시 포트를 차례로 쓴다(Windows·Linux 공통 범위 49152~65535).
        p = self.next_port.get(host, self.rng.randint(49152, 60000))
        self.next_port[host] = 49152 if p >= 65535 else p + 1
        return p

    def uniform(self, lo_hi):
        return self.rng.uniform(*lo_hi)

    def randint(self, lo_hi):
        return self.rng.randint(*lo_hi)


def conn_row(ctx, uid, ts, orig_h, orig_p, resp_h, resp_p, proto, service, duration, orig_bytes, resp_bytes,
             conn_state, history, orig_pkts, resp_pkts):
    # 필드 순서와 이름은 run-02 conn.log와 같다. IP 헤더 바이트는 패킷당 TCP 52·UDP 28을 더한다.
    overhead = 52 if proto == "tcp" else 28
    delay = ctx.delays[f"{proto}:{conn_state}"] + ctx.rng.uniform(0, 0.2)
    return {
        "_write_ts": round(ts + duration + delay, 6), "ts": round(ts, 6), "uid": uid,
        "id.orig_h": orig_h, "id.orig_p": orig_p, "id.resp_h": resp_h, "id.resp_p": resp_p,
        "proto": proto, **({"service": service} if service else {}), "duration": duration,
        "orig_bytes": orig_bytes, "resp_bytes": resp_bytes, "conn_state": conn_state,
        "local_orig": ipaddress.ip_address(orig_h).is_private, "local_resp": ipaddress.ip_address(resp_h).is_private,
        "missed_bytes": 0, "history": history, "orig_pkts": orig_pkts, "orig_ip_bytes": orig_bytes + overhead * orig_pkts,
        "resp_pkts": resp_pkts, "resp_ip_bytes": resp_bytes + overhead * resp_pkts, "ip_proto": PROTO_NUM[proto],
        "community_id": community_id(orig_h, orig_p, resp_h, resp_p, proto),
    }


def aux_row(conn, ts, **fields):
    # 프로토콜 로그 행. 연결 키는 conn과 같다. 기록 시각은 그 사건 직후로 둔다.
    return {"_write_ts": round(ts + 0.0005, 6), "ts": round(ts, 6), "uid": conn["uid"],
            "id.orig_h": conn["id.orig_h"], "id.orig_p": conn["id.orig_p"],
            "id.resp_h": conn["id.resp_h"], "id.resp_p": conn["id.resp_p"], **fields}


def dns_lookup(ctx, ep, ts, client, server, query, answer, qtype="A"):
    """클라이언트 → DNS 서버 UDP 53 질의 한 번(conn + dns)."""
    uid = ctx.uid()
    q = len(query)
    conn = conn_row(ctx, uid, ts, client, ctx.port(client), server, 53, "udp", "dns", round(ctx.uniform((0.0005, 0.03)), 6),
                    q + 18, q + 34, "SF", "Dd", 1, 1)
    ep.add("conn", conn)
    ep.add("dns", aux_row(conn, ts, proto="udp", trans_id=ctx.rng.randint(1, 65535), rtt=conn["duration"],
                          query=query, qclass=1, qclass_name="C_INTERNET", qtype={"A": 1, "TXT": 16}[qtype],
                          qtype_name=qtype, rcode=0, rcode_name="NOERROR", AA=False, TC=False, RD=True, RA=True, Z=0,
                          answers=[answer], TTLs=[300.0], rejected=False))
    ep.truth.append((uid, client, "originator", conn["_write_ts"]))
    return conn


def tls_conn(ctx, ep, ts, client, server, sni, orig_bytes, resp_bytes, duration, orig_pkts, resp_pkts):
    """클라이언트 → 외부 서버 443 TLS 연결(conn + ssl)."""
    uid = ctx.uid()
    conn = conn_row(ctx, uid, ts, client, ctx.port(client), server, 443, "tcp", "ssl", round(duration, 6),
                    orig_bytes, resp_bytes, "SF", "ShADadFf", orig_pkts, resp_pkts)
    ep.add("conn", conn)
    ep.add("ssl", aux_row(conn, ts + 0.05, version="TLSv12", cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                          curve="secp256r1", server_name=sni, resumed=False, established=True,
                          ssl_history="CsxknGIi", sni_matches_cert=True))
    ep.truth.append((uid, client, "originator", conn["_write_ts"]))
    return conn


def periodic_tls(ctx, ep, p, dns_server, c2_ip, domain, size_rule):
    """beacon_https·slow_exfil 공통: 흔들리는 간격의 TLS 연결 + 주기적 DNS 조회."""
    t, last_dns = ep.start, None
    while t < ep.start + p["duration_seconds"]:
        if last_dns is None or t - last_dns >= p["dns_every_seconds"]:
            dns_lookup(ctx, ep, t - 0.05, ep.attacker, dns_server, domain, c2_ip)
            last_dns = t
        tls_conn(ctx, ep, t, ep.attacker, c2_ip, domain, *size_rule())
        t += p["interval_seconds"] * ctx.rng.uniform(1 - p["jitter"], 1 + p["jitter"])


def beacon_https(ctx, attacker, start, p, dns_server, c2_ip, domain):
    ep = Episode("beacon_https", attacker, start)

    def size():
        return (ctx.randint(p["orig_bytes"]), ctx.randint(p["resp_bytes"]), ctx.uniform(p["conn_duration"]),
                ctx.randint(p["orig_pkts"]), ctx.randint(p["resp_pkts"]))

    periodic_tls(ctx, ep, p, dns_server, c2_ip, domain, size)
    return ep


def slow_exfil(ctx, attacker, start, p, dns_server, c2_ip, domain):
    ep = Episode("slow_exfil", attacker, start)

    def size():
        out = ctx.randint(p["orig_bytes"])
        pkts = out // 1400 + 1
        return out, ctx.randint(p["resp_bytes"]), ctx.uniform(p["conn_duration"]), pkts, pkts // 2 + 1

    periodic_tls(ctx, ep, p, dns_server, c2_ip, domain, size)
    return ep


def dns_tunnel(ctx, attacker, start, p, dns_server, domain):
    ep = Episode("dns_tunnel", attacker, start)
    t = start
    while t < start + p["duration_seconds"]:
        label = "".join(ctx.rng.choice(BASE32_CHARS) for _ in range(ctx.randint(p["label_len"])))
        seq = "".join(ctx.rng.choice(BASE32_CHARS) for _ in range(8))
        answer = f"10.{ctx.rng.randint(0, 255)}.{ctx.rng.randint(0, 255)}.{ctx.rng.randint(1, 254)}"
        dns_lookup(ctx, ep, t, attacker, dns_server, f"{label}.{seq}.{domain}", answer, p["qtype"])
        t += ctx.uniform(p["interval_seconds"])
    return ep


def lateral_smb(ctx, attacker, start, p, dc, targets):
    """대상마다: Kerberos TGS(DC) → SMB 445 ADMIN$ 매핑·파일 쓰기 → 135 epmapper → svcctl 서비스 생성·시작."""
    ep = Episode("lateral_smb", attacker, start)
    t = start
    for target in targets:
        uid = ctx.uid()
        krb = conn_row(ctx, uid, t, attacker, ctx.port(attacker), dc, 88, "tcp", "krb_tcp",
                       round(ctx.uniform((0.001, 0.01)), 6), ctx.randint((1400, 1700)), ctx.randint((1400, 1700)),
                       "SF", "ShADTadtFf", 6, 5)
        ep.add("conn", krb)
        ep.add("kerberos", aux_row(krb, t + 0.001, request_type="TGS", client="administrator/Testbed1.ca",
                                   service=f"cifs/{target}", success=True, till=2136422885.0,
                                   cipher="aes256-cts-hmac-sha1-96", forwardable=True, renewable=False))
        ep.truth.append((uid, attacker, "originator", krb["_write_ts"]))

        payload = ctx.randint(p["payload_bytes"])
        uid = ctx.uid()
        dur = ctx.uniform((2.0, 6.0))
        smb = conn_row(ctx, uid, t + 0.02, attacker, ctx.port(attacker), target, 445, "tcp", "gssapi,smb,krb",
                       round(dur, 6), payload + ctx.randint((3000, 6000)), ctx.randint((4000, 9000)), "RSTO",
                       "ShADTdtaR", payload // 1400 + 20, payload // 2800 + 15)
        ep.add("conn", smb)
        for share, kind in [("IPC$", "PIPE"), ("ADMIN$", "DISK")]:
            ep.add("smb_mapping", aux_row(smb, t + 0.05, path=f"\\\\{target}\\{share}", share_type=kind))
        name = "".join(ctx.rng.choice(string.ascii_letters) for _ in range(8)) + ".exe"
        ep.add("smb_files", aux_row(smb, t + 0.3, action="SMB::FILE_WRITE", path=f"\\\\{target}\\ADMIN$",
                                    name=name, size=payload))
        ep.truth += [(uid, attacker, "originator", smb["_write_ts"]), (uid, target, "responder", smb["_write_ts"])]

        for port, ops, endpoint in [(135, ["ept_map"], "epmapper"),
                                    (ctx.rng.randint(49664, 49690), ["OpenSCManagerW", "CreateServiceW",
                                                                      "StartServiceW", "CloseServiceHandle"], "svcctl")]:
            uid = ctx.uid()
            rt = t + dur + 0.1
            rpc = conn_row(ctx, uid, rt, attacker, ctx.port(attacker), target, port, "tcp", "dce_rpc",
                           round(ctx.uniform((0.01, 0.5)), 6), ctx.randint((300, 1500)), ctx.randint((200, 800)),
                           "SF", "ShADTdtFf", 8, 6)
            ep.add("conn", rpc)
            for k, op in enumerate(ops):
                ep.add("dce_rpc", aux_row(rpc, rt + 0.002 * (k + 1), rtt=0.0003, named_pipe=str(port),
                                          endpoint=endpoint, operation=op))
            ep.truth += [(uid, attacker, "originator", rpc["_write_ts"]), (uid, target, "responder", rpc["_write_ts"])]
        t += dur + ctx.uniform(p["gap_seconds"])
    return ep


def internal_scan(ctx, attacker, start, p, targets, linux_hosts):
    """대상 × 포트를 섞어 한 번씩 connect scan. 열린 포트는 RSTO(ShAR), 닫힌 포트는 REJ(Sr)."""
    ep = Episode("internal_scan", attacker, start)
    probes = [(h, port) for h in targets for port in p["ports"]]
    ctx.rng.shuffle(probes)
    t = start
    for target, port in probes:
        is_open = port == 22 if target in linux_hosts else port in (135, 139, 445)
        uid = ctx.uid()
        if is_open:
            conn = conn_row(ctx, uid, t, attacker, ctx.port(attacker), target, port, "tcp", None,
                            round(ctx.uniform((0.0005, 0.002)), 6), 0, 0, "RSTO", "ShAR", 3, 1)
        else:
            conn = conn_row(ctx, uid, t, attacker, ctx.port(attacker), target, port, "tcp", None,
                            round(ctx.uniform((0.0002, 0.0008)), 6), 0, 0, "REJ", "Sr", 1, 1)
        ep.add("conn", conn)
        ep.truth += [(uid, attacker, "originator", conn["_write_ts"]), (uid, target, "responder", conn["_write_ts"])]
        t += ctx.uniform(p["interval_seconds"])
    return ep


def random_domain(rng, tlds):
    letters = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(8, 12)))
    return f"{letters}.{rng.choice(tlds)}"


def truth_windows(ep, window_seconds):
    """에피소드의 정답 창: (자산, 역할, window_start) 집합."""
    return {(asset, role, int(w // window_seconds) * window_seconds) for _, asset, role, w in ep.truth}
