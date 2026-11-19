"""사건 근거 요약과 자산 관측(단계 4 5번, DD-010).

- 근거 요약: 사건 창에서 그 자산·역할의 연결을 모아 ECS 이름의 JSON으로 요약한다. 숫자는 모두 코드가 센다.
  문자열 필드(DNS 질의, HTTP URI·호스트, SNI)는 v1에 넣지 않는다. 비신뢰 입력이고 LLM 입력 허용 목록 밖이다(설계 9.1절).
- 자산 관측: Zeek kerberos·ntlm 로그에 실제로 나온 이름만 출처와 함께 모은다. 관측하지 않은 값을 만들지 않는다.
"""

from collections import defaultdict
from datetime import datetime, timezone
import json

import pandas as pd

EVIDENCE_VERSION = "evidence.v1"
EVENT_COLUMNS = ["window_start", "uid", "ts", "orig_h", "orig_p", "resp_h", "resp_p", "proto", "service", "duration",
                 "orig_bytes", "resp_bytes", "orig_ip_bytes", "resp_ip_bytes", "conn_state", "dns_n", "dns_query_len_max", "dns_nxdomain_n", "http_n",
                 "http_error_n", "ssl_version", "ssl_sni", "ssh_auth_success", "ftp_fail_n", "smb_map_n", "smb_file_n",
                 "krb_n", "krb_fail_n", "dce_n", "dce_operation", "ntlm_n", "ntlm_fail_n"]
TOP = 5
REPRESENTATIVE = 10
LIMITS = [
    "Zeek 네트워크 메타데이터만 본다. 호스트의 프로세스·사용자 행위(EDR)는 관측하지 않았다",
    "점수는 정상(월요일) 대비 이상함이다. 공격 확정이 아니다",
    "모델끼리 점수 척도가 다르다. picked_by 모델의 점수만 그 모델 임계값과 비교한다",
    "바이트는 관측한 IP 바이트다. Zeek 페이로드 바이트가 IP 바이트보다 큰(부푼) 연결 수는 network.zeekad_payload_bytes_inflated",
]


def iso(seconds):
    return datetime.fromtimestamp(float(seconds), timezone.utc).isoformat().replace("+00:00", "Z")


def _num(v):
    return 0 if pd.isna(v) else v


def summarize_incident(rows, asset, role, first_start, last_end):
    """rows: 사건 창에 든, 그 자산이 role 쪽인 연결(이벤트 표 행). 반환: ECS 이름의 근거 JSON."""
    is_orig = role == "originator"
    peer = rows.resp_h if is_orig else rows.orig_h
    # 바이트는 실제로 관측한 IP 바이트(*_ip_bytes)를 쓴다. Zeek의 orig_bytes·resp_bytes는 TCP 시퀀스 번호로 계산해서
    # 비정상 종료·패킷 손실 연결에서 크게 부풀 수 있다(수요일 DoS 사건 창 724개 연결, 합계 1TB 대 실제 124MB).
    sent = rows.orig_ip_bytes if is_orig else rows.resp_ip_bytes
    received = rows.resp_ip_bytes if is_orig else rows.orig_ip_bytes
    inflated = (rows.orig_bytes.fillna(0) > rows.orig_ip_bytes) | (rows.resp_bytes.fillna(0) > rows.resp_ip_bytes)
    protocol = rows.service.fillna("unidentified").str.split(",").str[0]
    ports = rows.groupby([rows.resp_p.astype("Int64"), rows.proto]).size().sort_values(ascending=False)
    dce = rows.dce_operation.dropna().value_counts()

    # 대표 연결: 상대(peer)별 첫 연결을 상대의 연결 수 순으로, 모자라면 시간순으로 채운다. 같은 입력이면 같은 결과다.
    ordered = rows.sort_values(["ts", "uid"])
    peer_rank = peer.value_counts()
    firsts = ordered.groupby(peer.loc[ordered.index], sort=False).head(1)
    firsts = firsts.assign(_n=peer.loc[firsts.index].map(peer_rank)).sort_values(["_n", "ts"], ascending=[False, True])
    picked = list(firsts.index[:REPRESENTATIVE])
    picked += [i for i in ordered.index if i not in set(picked)][:REPRESENTATIVE - len(picked)]

    def connection(r):
        return {"zeek": {"uid": r.uid, "conn_state": r.conn_state},
                "event": {"start": iso(r.ts), "duration": None if pd.isna(r.duration) else float(r.duration)},
                "source": {"ip": r.orig_h, "port": int(r.orig_p), "bytes": int(_num(r.orig_ip_bytes))},
                "destination": {"ip": r.resp_h, "port": int(r.resp_p), "bytes": int(_num(r.resp_ip_bytes))},
                "network": {"transport": r.proto, "protocol": None if pd.isna(r.service) else r.service}}

    return {
        "version": EVIDENCE_VERSION,
        "host": {"ip": asset}, "zeekad_role": role,
        "event": {"start": iso(first_start), "end": iso(last_end)},
        "connection_count": len(rows),
        "network": {"transport": rows.proto.value_counts().to_dict(), "protocol": protocol.value_counts().to_dict(),
                    "bytes": {"sent": int(sent.fillna(0).sum()), "received": int(received.fillna(0).sum())},
                    "zeekad_payload_bytes_inflated": int(inflated.sum())},
        "zeek_conn_state": rows.conn_state.value_counts().to_dict(),
        "peers": {"unique": int(peer.nunique()),
                  "top": [{"ip": ip, "connections": int(n)} for ip, n in peer_rank.head(TOP).items()]},
        "destination_ports": {"unique": int(len(ports)),
                              "top": [{"port": int(p), "transport": t, "connections": int(n)}
                                      for (p, t), n in ports.head(TOP).items()]},
        "protocol_logs": {
            "dns": {"queries": int(rows.dns_n.fillna(0).sum()), "nxdomain": int(rows.dns_nxdomain_n.fillna(0).sum()),
                    "max_query_length": int(rows.dns_query_len_max.fillna(0).max() or 0)},
            "http": {"requests": int(rows.http_n.fillna(0).sum()), "errors": int(rows.http_error_n.fillna(0).sum())},
            "tls": {"connections": int(rows.ssl_version.notna().sum()),
                    "without_sni": int((rows.ssl_version.notna() & rows.ssl_sni.isna()).sum())},
            "ssh": {"auth_failures": int((rows.ssh_auth_success == False).sum())},  # noqa: E712 (null은 제외)
            "ftp": {"failed_replies": int(rows.ftp_fail_n.fillna(0).sum())},
            "smb": {"mappings": int(rows.smb_map_n.fillna(0).sum()), "files": int(rows.smb_file_n.fillna(0).sum())},
            "kerberos": {"requests": int(rows.krb_n.fillna(0).sum()), "failures": int(rows.krb_fail_n.fillna(0).sum())},
            "dce_rpc": {"calls": int(rows.dce_n.fillna(0).sum()),
                        "top_operations": [{"operation": op, "connections": int(n)} for op, n in dce.head(TOP).items()]},
            "ntlm": {"auths": int(rows.ntlm_n.fillna(0).sum()), "failures": int(rows.ntlm_fail_n.fillna(0).sum())},
        },
        "representative_connections": [connection(rows.loc[i]) for i in picked],
        "limits": LIMITS,
    }


def incident_rows(events, asset, role, windows):
    """이벤트 표에서 사건 창에 든, 자산이 role 쪽인 연결."""
    side = events.orig_h if role == "originator" else events.resp_h
    return events[(side == asset) & events.window_start.isin(windows)]


def asset_observations(run_dir, capture_id, is_asset):
    """kerberos.log의 client, ntlm.log의 hostname·username을 요청을 보낸 주소(id.orig_h)의 관측으로 모은다.

    is_asset(ip): 점수 대상 자산인지. 반환: 행 dict 목록(asset_observation 표 형식).
    """
    acc = defaultdict(lambda: {"n": 0, "first": None, "last": None})

    def add(ip, kind, value, source, ts):
        if not value or not is_asset(ip):
            return
        a = acc[(ip, kind, value, source)]
        a["n"] += 1
        a["first"] = ts if a["first"] is None else min(a["first"], ts)
        a["last"] = ts if a["last"] is None else max(a["last"], ts)

    def lines(name):
        # 그날 그 프로토콜이 없으면 Zeek가 로그 파일을 만들지 않는다(실습망 캡처, DD-012). 관측 없음으로 본다.
        path = run_dir / name
        return path.open(encoding="utf-8") if path.exists() else ()

    for line in lines("kerberos.log"):
        r = json.loads(line)
        client = (r.get("client") or "").split("/")[0]
        if client:
            add(r["id.orig_h"], "kerberos_machine" if client.endswith("$") else "kerberos_user", client,
                "kerberos.log", r["ts"])
    for line in lines("ntlm.log"):
        r = json.loads(line)
        add(r["id.orig_h"], "ntlm_hostname", r.get("hostname"), "ntlm.log", r["ts"])
        add(r["id.orig_h"], "ntlm_user", r.get("username"), "ntlm.log", r["ts"])
    return [{"capture_id": capture_id, "asset_id": ip, "kind": kind, "value": value, "source_log": source,
             "observations": a["n"], "first_seen": datetime.fromtimestamp(a["first"], timezone.utc),
             "last_seen": datetime.fromtimestamp(a["last"], timezone.utc)}
            for (ip, kind, value, source), a in sorted(acc.items())]
