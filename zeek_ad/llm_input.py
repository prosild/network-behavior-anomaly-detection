"""LLM·판단 모델에 보낼 사건 입력 만들기(단계 5b-1, 설계 9.1절 입력 경계).

근거(evidence.v1)에는 실제 IP·날짜·Zeek uid가 있다. 여기서 허용 목록에 있는 값만 골라 "사실 목록"으로 펼친다.
- 사실 하나 = {"id": "F01", "name": 이름, "value": 값}. 보고서의 주장마다 사실 ID를 달게 해서, 코드가 주장의 숫자를 검사한다.
- 값은 숫자·불리언·검증한 열거값(전송 계층, Zeek 서비스·연결 상태, DCE-RPC 연산 이름)·가명·고정 설명만 쓴다.
  도메인·URI·SNI·사용자·호스트 이름 같은 자유 문자열은 넣지 않는다.
- IP는 관계를 지키는 가명으로 바꾼다: 사건 자산 H, 내부 상대 I1·I2…, 외부 상대 X1·X2…(내부 = 자산 설정의 내부망).
- 시각은 사건 시작 기준 상대 초로 바꾼다. 날짜·요일을 보내지 않는다.
- v2: 비교 기준(같은 자산·역할의 월요일 학습 창 분포)과 모델 설명을 더하고, 단위가 헷갈리는 사실 이름에 단위를 붙였다(Q41).
가명화가 데이터셋 암기를 완전히 막는다고 주장하지 않는다(설계 9.1절).
"""

from datetime import datetime
import ipaddress
import re

INPUT_VERSION = "llm-input.v2"
TRANSPORTS = {"tcp", "udp", "icmp"}
CONN_STATES = {"S0", "S1", "S2", "S3", "SF", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"}
ZEEK_SERVICES = {"dns", "http", "ssl", "ssh", "ftp", "ftp-data", "smtp", "smb", "krb", "krb_tcp", "dce_rpc", "ntlm",
                 "gssapi", "ntp", "dhcp", "snmp", "rdp", "irc", "mysql", "pop3", "imap", "sip", "socks", "syslog",
                 "radius", "ldap", "ldap_tcp", "quic", "unidentified"}
MODELS = {"tgn_recon", "tail_rarity_v2", "transformer_v2"}
DCE_OPERATION = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
REPRESENTATIVE = 5
# 모델 이름만 보내면 LLM이 뜻을 짐작한다(시험 호출에서 tgn_recon의 recon을 정찰로 읽었다). 고정 설명을 함께 보낸다.
MODEL_DESCRIPTIONS = {
    "tgn_recon": "Temporal graph network over host-peer connections. Score = reconstruction error of each connection "
                 "('recon' means reconstruction, not reconnaissance). High when connection patterns differ from Monday",
    "tail_rarity_v2": "Per-feature rarity against Monday windows of all hosts pooled. Score = rarity of the most unusual "
                      "feature in the window",
    "transformer_v2": "Sequence model. Score = error predicting this window from the previous 12 windows (1 hour) of "
                      "the same host and role, trained on Monday",
}
# 근거 키 중 단위가 이름에 드러나지 않는 것. 시험 호출에서 DNS 이름 길이 72(문자 수)를 바이트로 읽었다.
RENAMED = {"dns.max_query_length": "dns.max_query_length_chars"}
# 비교 기준에 쓰는 Gold v2 특징 → 사실 이름(단위 포함). 결과를 보기 전에 정한 고정 목록이다.
# ALWAYS는 늘 보내고, IF_ACTIVE는 사건 최대값이나 기준 p95가 0보다 클 때만 보낸다(사실 수를 줄인다).
BASELINE_ALWAYS = {
    "conn_count": "connections_per_window",
    "peer_count": "distinct_peers_per_window",
    "peer_port_count": "distinct_peer_ports_per_window",
    "out_bytes_sum": "payload_bytes_sent_by_host_per_window",
    "in_bytes_sum": "payload_bytes_received_by_host_per_window",
    "unestablished_ratio": "unestablished_connection_ratio",
}
BASELINE_IF_ACTIVE = {
    "rejected_ratio": "rejected_connection_ratio",
    "icmp_ratio": "icmp_connection_ratio",
    "dns_query_count": "dns_queries_per_window",
    "dns_nxdomain_count": "dns_nxdomain_per_window",
    "dns_query_len_max": "dns_max_query_length_chars",
    "http_request_count": "http_requests_per_window",
    "http_error_count": "http_errors_per_window",
    "ssl_no_sni_count": "tls_without_sni_per_window",
    "ssh_auth_fail_count": "ssh_auth_failures_per_window",
    "ftp_fail_count": "ftp_failures_per_window",
    "smb_map_count": "smb_mappings_per_window",
    "smb_file_count": "smb_file_actions_per_window",
    "dce_op_count": "dce_rpc_calls_per_window",
    "krb_fail_count": "kerberos_failures_per_window",
    "ntlm_fail_count": "ntlm_failures_per_window",
}
BASELINE_FEATURES = {**BASELINE_ALWAYS, **BASELINE_IF_ACTIVE}
# 고정 설명. evidence.v1의 한계 문장과 같은 뜻이다(사건과 무관한 고정 글이라 보내도 된다).
LIMITS = [
    "Zeek network metadata only; host process and user activity (EDR) were not observed",
    "Scores measure deviation from normal (Monday) traffic; they do not confirm an attack",
    "Byte counts are observed IP bytes; payload_bytes_inflated counts connections whose Zeek payload bytes exceed IP bytes",
    "Peers are pseudonyms: H is this host, I* are internal peers, X* are external peers. Times are seconds from incident start",
    "baseline.* facts compare the incident's 5-minute windows (max) with Monday training windows of the same host and "
    "role (p50, p95, max). Monday covers one day without time-of-day matching; few baseline windows make it weak",
]


# 템플릿 보고서(화면·Slack)에 쓰는 한계 문장. LIMITS(LLM 입력용 영어)와 같은 뜻이다.
LIMITS_KO = [
    "Zeek 네트워크 메타데이터만 봤다. 호스트의 프로세스·사용자 활동(EDR)은 관측하지 않았다",
    "점수는 정상(월요일) 트래픽과의 차이다. 공격을 확정하지 않는다",
    "바이트 수는 관측한 IP 바이트다. payload_bytes_inflated는 Zeek 페이로드 바이트가 IP 바이트보다 큰 연결 수다",
    "상대는 가명이다: H는 이 자산, I*는 내부 상대, X*는 외부 상대. 시각은 사건 시작부터 센 초다",
    "baseline.* 사실은 사건 5분 창의 최댓값을 같은 자산·역할의 월요일 학습 창(p50·p95·최대)과 비교한다. "
    "월요일 하루뿐이고 시간대를 맞추지 않았으며, 월요일 창이 적으면 비교가 약하다",
]


class Pseudonyms:
    """같은 IP는 항상 같은 가명. 처음 본 순서대로 번호를 매긴다."""

    def __init__(self, host, internal_networks):
        self.map = {host: "H"}
        self.nets = [ipaddress.ip_network(n) for n in internal_networks]
        self.count = {"I": 0, "X": 0}

    def __call__(self, ip):
        if ip not in self.map:
            zone = "I" if any(ipaddress.ip_address(ip) in n for n in self.nets) else "X"
            self.count[zone] += 1
            self.map[ip] = f"{zone}{self.count[zone]}"
        return self.map[ip]


def _enum(value, allowed, other="other"):
    return value if value in allowed else other


def _seconds(iso_text, origin):
    return round((datetime.fromisoformat(iso_text.replace("Z", "+00:00")) - origin).total_seconds(), 3)


def percentile(values, q):
    """선형 보간 분위수(pandas 기본값과 같다). values는 None이 없는 숫자 목록."""
    xs = sorted(values)
    if not xs:
        return None
    pos = (len(xs) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def _round(x):
    if x is None:
        return None
    return round(x, 3) if abs(x) < 10 else round(x)


def baseline_facts(incident_windows, baseline_windows):
    """사건 창과 월요일 학습 창(같은 자산·역할)의 Gold 특징 → (사실 이름, 값) 목록.

    incident_windows·baseline_windows: 창마다 {Gold 특징: 값} 사전 목록. 값이 None(창 안 모든 값이 결측)이면 뺀다.
    기준 창이 0개면 분위수는 None이다. 판단은 하지 않고 숫자만 나란히 둔다.
    """
    out = [("baseline_windows", {"incident_windows": len(incident_windows),
                                 "baseline_windows": len(baseline_windows)})]
    for col, name in BASELINE_FEATURES.items():
        inc = [w[col] for w in incident_windows if w.get(col) is not None]
        base = [w[col] for w in baseline_windows if w.get(col) is not None]
        inc_max = max(inc) if inc else None
        p95 = percentile(base, 0.95)
        if col in BASELINE_IF_ACTIVE and not ((inc_max or 0) > 0 or (p95 or 0) > 0):
            continue
        out.append((f"baseline.{name}", {"incident_max": _round(inc_max), "baseline_p50": _round(percentile(base, 0.5)),
                                         "baseline_p95": _round(p95), "baseline_max": _round(max(base) if base else None)}))
    return out


def build_facts(evidence, incident, model_windows, internal_networks, baseline=()):
    """근거 JSON·사건 행·모델별 창 수 → 사실 목록.

    incident: {"queue_rank", "picked_by", "also_flagged_by", "zeekad_role"}.
    model_windows: {모델 이름: (후보 창 수, 사건 창 수)}.
    baseline: baseline_facts()의 결과. 비교 기준 사실로 그대로 붙인다.
    """
    pseudo = Pseudonyms(evidence["host"]["ip"], internal_networks)
    start = datetime.fromisoformat(evidence["event"]["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(evidence["event"]["end"].replace("Z", "+00:00"))
    facts = []

    def add(name, value):
        facts.append({"id": f"F{len(facts) + 1:02d}", "name": name, "value": value})

    # 사건과 모델 의견
    add("host_role", _enum(evidence["zeekad_role"], {"originator", "responder"}))
    add("incident_duration_seconds", int((end - start).total_seconds()))
    add("queue_rank", int(incident["queue_rank"]))
    add("picked_by_model", _enum(incident["picked_by"], MODELS))
    add("also_flagged_by_models", sorted(_enum(m, MODELS) for m in incident["also_flagged_by"]))
    for m in sorted(model_windows):
        cand, total = model_windows[m]
        add(f"model_candidate_windows.{_enum(m, MODELS)}", {"candidate": int(cand), "windows": int(total)})

    # 연결 통계
    net = evidence["network"]
    add("connection_count", int(evidence["connection_count"]))
    for t, n in sorted(net["transport"].items()):
        add(f"transport.{_enum(t, TRANSPORTS)}", int(n))
    for p, n in sorted(net["protocol"].items(), key=lambda kv: -kv[1]):
        add(f"protocol.{_enum(p, ZEEK_SERVICES)}", int(n))
    add("bytes_sent_by_host", int(net["bytes"]["sent"]))
    add("bytes_received_by_host", int(net["bytes"]["received"]))
    add("payload_bytes_inflated_connections", int(net["zeekad_payload_bytes_inflated"]))
    for s, n in sorted(evidence["zeek_conn_state"].items(), key=lambda kv: -kv[1]):
        add(f"conn_state.{_enum(s, CONN_STATES)}", int(n))

    # 상대와 포트
    add("unique_peers", int(evidence["peers"]["unique"]))
    for k, p in enumerate(evidence["peers"]["top"], 1):
        add(f"top_peer_{k}", {"peer": pseudo(p["ip"]), "connections": int(p["connections"])})
    add("unique_destination_ports", int(evidence["destination_ports"]["unique"]))
    for k, p in enumerate(evidence["destination_ports"]["top"], 1):
        add(f"top_destination_port_{k}", {"port": int(p["port"]), "transport": _enum(p["transport"], TRANSPORTS),
                                          "connections": int(p["connections"])})

    # 프로토콜 로그(숫자만). DCE-RPC 연산 이름은 형식을 검사한 열거값이다.
    for log, values in sorted(evidence["protocol_logs"].items()):
        for key, v in sorted(values.items()):
            if key == "top_operations":
                for k, op in enumerate(v, 1):
                    name = op["operation"] if DCE_OPERATION.match(op["operation"] or "") else "other"
                    add(f"{log}.top_operation_{k}", {"operation": name, "connections": int(op["connections"])})
            else:
                name = f"{log}.{key}"
                add(RENAMED.get(name, name), int(v))

    # 비교 기준(Q41): 같은 자산·역할의 월요일 학습 창 분포와 사건 창 최대값
    for name, value in baseline:
        add(name, value)

    # 대표 연결: 가명·상대 초. uid는 보내지 않는다(Zeek 실행 안에서만 뜻이 있고 조회 API로 찾을 수 있다).
    for k, c in enumerate(evidence["representative_connections"][:REPRESENTATIVE], 1):
        add(f"example_connection_{k}", {
            "source": pseudo(c["source"]["ip"]), "destination": pseudo(c["destination"]["ip"]),
            "destination_port": int(c["destination"]["port"]),
            "transport": _enum(c["network"]["transport"], TRANSPORTS),
            "protocol": _enum(c["network"]["protocol"] or "unidentified", ZEEK_SERVICES),
            "conn_state": _enum(c["zeek"]["conn_state"], CONN_STATES),
            "start_seconds": _seconds(c["event"]["start"], start),
            "duration_seconds": None if c["event"]["duration"] is None else round(c["event"]["duration"], 3),
            "source_bytes": int(c["source"]["bytes"]), "destination_bytes": int(c["destination"]["bytes"])})
    return facts


def fact_map(facts):
    return {f["name"]: f for f in facts}


def _share(n, total):
    return n / total if total else 0.0


def query_sentence(facts):
    """사실 목록 → ATT&CK 검색용 영어 문장. Zeek로 보이는 행동만 쓴다(5a 질의 세트와 같은 꼴).

    문장을 고르는 규칙은 결과를 보기 전에 정했다. 탐지 규칙이 아니라 검색어를 만드는 규칙이다.
    """
    f = fact_map(facts)
    v = lambda name, default=0: f[name]["value"] if name in f else default  # noqa: E731
    total = v("connection_count")
    origin = v("host_role") == "originator"
    parts = []

    top = v("top_peer_1", None)
    peers = v("unique_peers")
    if top and _share(top["connections"], total) >= 0.8:
        zone = "an internal" if top["peer"].startswith("I") else "an external"
        parts.append(f"{'Host connects to' if origin else 'Host receives connections from'} mostly {zone} peer")
    else:
        parts.append(f"{'Host connects to' if origin else 'Host receives connections from'} {peers} peers")

    protos = [(n[len("protocol."):], x["value"]) for n, x in f.items() if n.startswith("protocol.")]
    named = [(p, n) for p, n in protos if p not in ("unidentified", "other")]
    port = v("top_destination_port_1", None)
    parts.append(f"{total} connections")
    if named:
        p, n = max(named, key=lambda pn: pn[1])
        parts.append(f"{'mostly' if _share(n, total) >= 0.5 else 'partly'} {p.upper()} traffic")
    if port and port["transport"] in ("tcp", "udp"):
        parts.append(f"top destination port {port['port']}/{port['transport']}")
    elif port:  # ICMP의 "포트"는 Zeek가 넣은 ICMP 유형·코드라 포트로 쓰지 않는다
        parts.append("ICMP messages" if port["transport"] == "icmp" else "non-TCP/UDP traffic")
    if v("unique_destination_ports") >= 20:
        parts.append(f"{v('unique_destination_ports')} distinct destination ports")
    if peers >= 20:
        parts.append("many distinct hosts")

    reset = sum(v(f"conn_state.{s}") for s in ("RSTO", "RSTR", "RSTOS0", "RSTRH"))
    if _share(v("conn_state.REJ"), total) >= 0.3:
        parts.append("most connections rejected")
    if _share(v("conn_state.S0"), total) >= 0.3:
        parts.append("most connection attempts unanswered")
    if _share(reset, total) >= 0.3:
        parts.append("many connections reset")

    if v("ssh.auth_failures"):
        parts.append("repeated SSH authentication failures")
    if v("ftp.failed_replies"):
        parts.append("failed FTP logins")
    if v("http.requests") and _share(v("http.errors"), v("http.requests")) >= 0.1:
        parts.append("many HTTP error responses")
    if v("dns.queries") and _share(v("dns.nxdomain"), v("dns.queries")) >= 0.1:
        parts.append("many DNS NXDOMAIN responses")
    # 최대 DNS 이름 길이는 쓰지 않는다: 정상 AD 질의도 72자까지 간다(개발 세트 실측). 분포가 없어 터널과 구분할 수 없다.
    if v("tls.connections") and _share(v("tls.without_sni"), v("tls.connections")) >= 0.5:
        parts.append("TLS without server name")
    # 있기만 한 신호는 넣지 않는다. 도메인 환경에서는 SMB·Kerberos·DCE-RPC가 늘 조금씩 있다.
    # 연결의 10% 이상일 때만 행동으로 쓴다(개발 세트 dev-11: DoS 15만 건 중 SMB 10건이 검색 1위를 바꿨다).
    if _share(v("smb.mappings"), total) >= 0.1:
        parts.append("SMB share mappings")
    if _share(v("smb.files"), total) >= 0.1:
        parts.append("SMB file writes or reads")
    ops = [x["value"]["operation"] for n, x in f.items() if n.startswith("dce_rpc.top_operation_")]
    if ops and _share(v("dce_rpc.calls"), total) >= 0.1:
        parts.append("DCE-RPC calls " + ", ".join(o for o in ops if o != "other"))
    if _share(v("kerberos.requests"), total) >= 0.1:
        parts.append("Kerberos ticket requests")
    if v("ntlm.failures"):
        parts.append("NTLM authentication failures")
    sent, received = v("bytes_sent_by_host"), v("bytes_received_by_host")
    if sent >= 1_000_000 and sent >= 5 * max(received, 1):
        parts.append("much more data sent than received")
    return "; ".join(parts)


def template_report(facts, attack_candidates):
    """LLM 없이 만드는 고정 템플릿 보고서(설계 9.1절 필드). LLM 실패 시 대신 쓰고, LLM 보고서와 비교한다.

    attack_candidates: [{"attack_id", "name"}] 검색 상위 문서. 가설로만 쓴다.
    """
    f = fact_map(facts)
    v = lambda name: f[name]  # noqa: E731
    claims = [
        {"claim": f"사건 창에서 이 자산({v('host_role')['value']})의 연결 {v('connection_count')['value']}건을 관측했다",
         "fact_ids": [v("host_role")["id"], v("connection_count")["id"]]},
        {"claim": f"고유 상대 {v('unique_peers')['value']}개, 고유 목적지 포트 {v('unique_destination_ports')['value']}개",
         "fact_ids": [v("unique_peers")["id"], v("unique_destination_ports")["id"]]},
    ]
    if "top_peer_1" in f:
        p = v("top_peer_1")
        claims.append({"claim": f"가장 많은 상대는 {p['value']['peer']}({p['value']['connections']}건)",
                       "fact_ids": [p["id"]]})
    if "top_destination_port_1" in f:
        p = v("top_destination_port_1")
        claims.append({"claim": f"가장 많은 목적지 포트는 {p['value']['port']}/{p['value']['transport']}"
                                f"({p['value']['connections']}건)", "fact_ids": [p["id"]]})
    claims.append({"claim": f"사건 큐 {v('queue_rank')['value']}위, {v('picked_by_model')['value']} 모델이 꼽았다",
                   "fact_ids": [v("queue_rank")["id"], v("picked_by_model")["id"]]})
    return {
        "report_version": "template.v1",
        "observation_summary": f"{v('incident_duration_seconds')['value'] // 60}분 동안 연결 "
                               f"{v('connection_count')['value']}건이 정상(월요일) 대비 이상하다고 판정됐다",
        "claims": claims,
        "possible_explanations": [f"ATT&CK 후보(가설): {c['attack_id']} {c['name']}" for c in attack_candidates],
        "limitations": ["템플릿 보고서다. 사실을 나열할 뿐 해석하지 않는다"] + LIMITS_KO,
        "follow_up": ["근거 조회 API에서 대표 연결과 상대별 연결을 확인한다",
                      "같은 자산의 이전·이후 사건과 비교한다"],
    }
