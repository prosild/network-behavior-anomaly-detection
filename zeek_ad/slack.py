"""Slack 알림 메시지 만들기와 전송 기록(DD-001 Slack 전송 규약, 단계 5b).

- 보내는 것(허용 목록): 캡처·큐 순위·자산·역할·시간 범위·꼽은 모델, 보고서의 관측 요약과 주장 몇 개(근거 사실 번호 포함),
  보고서 종류, 판단 기록, 근거 조회 링크. 원문 로그·도메인·사용자 이름은 보내지 않는다.
- LLM이 쓴 글은 믿지 않는 입력이다. Slack mrkdwn은 <!channel>, <@U123>, <http://x|글자> 같은 표기를 해석하므로
  & < > 를 이스케이프해 글자로만 보이게 한다(Slack 문서의 텍스트 이스케이프 규칙).
- 가명: 보고서 본문은 LLM 입력과 같은 가명(H·I*·X*)이다. Slack은 외부 서비스라 사건 자산(H)만 실제 주소로 밝히고,
  상대 주소는 내보내지 않는다. 실제 주소는 내부 대시보드·근거 API에서 본다(사용자 결정, 2026-11-17).
- 중복 방지: (job_id, incident_id, report_version)이 DB 기본 키다. 이미 있으면 다시 기록하지 않는다.
  다른 작업에서 이미 알린 사건은 알리지 않는다(alerted_before, DD-016 결정 4). 호출하는 쪽(agent_graph 등)이 확인한다.
- 같은 자산 알림 묶음(DD-010 결정 5): 설정에 grouping이 있으면 record_delivery가 묶음을 정한다(group_alert).
  같은 자산·역할의 미해결 알림 묶음이 60분 안에 있으면 새 사건 알림은 그 묶음 머리 알림의 스레드 답글이 된다.
  묶음 안에서 마지막으로 채널에 알린 지 30분이 지났으면 답글을 채널에도 띄운다(reply_broadcast, 재알림).
  시간은 알림을 만든 시각이 아니라 사건의 관측 시각이다(다시 계산이 밀려도 묶음이 흔들리지 않게).
  같은 사건의 뒤 알림(LLM 보고서 추가, 상태 변경)은 그 사건이 속한 스레드의 답글이고 채널에는 띄우지 않는다.
메시지 형식은 Slack Block Kit(chat.postMessage의 text·blocks)이다.
"""

import hashlib
import json
from pathlib import Path

from zeek_ad.provenance import PROJECT_ROOT


def escape(text):
    """Slack 제어 문자 이스케이프. 순서가 중요하다(& 먼저)."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cut(text, limit):
    text = escape(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def incident_message(incident, report, report_kind, decision, config, note=None):
    """사건 알림 메시지. incident: DB 사건 행(dict), report: 화면용 보고서, decision: send_decision 행(dict).

    먼저 보내는 알림(Q47)은 정책 규칙만 정한 상태라 decision의 llm_choice·decision_model이 None이다.
    note: 머리말 아래에 붙이는 한 줄(예: "LLM 보고서 추가").
    """
    rank, job = incident["queue_rank"], incident["job_id"]
    link = f"{config['api_base_url']}/api/v1/jobs/{job}/incidents/{rank}"
    when = f"{incident['first_start']:%Y-%m-%d %H:%M}~{incident['last_end']:%H:%M} UTC"
    models = ", ".join([incident["picked_by"], *incident["also_flagged_by"]])
    claims = []
    for c in report.get("claims", [])[: config["max_claims"]]:
        ids = ", ".join(escape(i) for i in c["fact_ids"])
        claims.append(f"• {_cut(c['claim'], 400)} _({ids})_")
    dm = decision["decision_model"]
    shadow = (f"정책 규칙 {decision['policy']['choice']}"
              f"{' (필수: ' + '; '.join(decision['policy']['reasons']) + ')' if decision['policy']['mandatory'] else ''}")
    if dm is None:
        shadow += " · LLM 보고서와 판단 모델 의견은 뒤따른다"
    else:
        shadow += f" · LLM {decision['llm_choice']} · 판단 모델 {dm.get('choice')}"
    header = f"[{incident['capture_id']}] 조사 큐 {rank}위 · {incident['asset']} ({incident['role']})"
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": header[:150]}},
        *([{"type": "context", "elements": [{"type": "mrkdwn", "text": f"*{escape(note)}*"}]}] if note else []),
        {"type": "context", "elements": [{"type": "mrkdwn", "text": (
            f"H = {escape(incident['asset'])} · I*·X*는 내부·외부 상대의 가명이다. "
            "실제 주소는 [근거 보기](내부 대시보드·근거 API)에서 확인한다")}]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*시간*\n{when}"},
            {"type": "mrkdwn", "text": f"*꼽은 모델*\n{escape(models)}"}]},
        {"type": "section", "text": {"type": "mrkdwn",
                                     "text": "*관측 요약*\n" + _cut(report["observation_summary"],
                                                                 config["max_text_chars"])}},
    ]
    if claims:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*주요 근거*\n" + "\n".join(claims)}})
    blocks += [
        {"type": "context", "elements": [{"type": "mrkdwn", "text": (
            f"보고서 {report_kind} ({escape(report.get('report_version', ''))}) · {escape(shadow)} · "
            "점수는 정상(월요일) 대비 차이이며 공격 확정이 아님")}]},
        {"type": "actions", "elements": [{"type": "button", "text": {"type": "plain_text", "text": "근거 보기"},
                                          "url": link}]},
    ]
    text = f"{header} — {_cut(report['observation_summary'], 200)}"  # 알림 미리보기용
    return {"channel": config["channel"], "text": text, "blocks": blocks}


def alerted_before(conn, job_id, incident_id):
    """이 사건(사건 ID)을 이전 채점 작업에서 이미 알렸는가(DD-016 결정 4, Q55).

    실습망은 같은 날을 여러 번 다시 계산하므로 같은 사건이 작업마다 나온다. 사건이 늘어나 보고서를 다시 만들어도
    Slack에는 다시 보내지 않는다(대시보드가 최신 보고서를 보여 준다). 같은 작업 안의 두 번째 알림(템플릿 다음 LLM 보고서)은
    막지 않는다. 상태 변경 알림(report_version이 status:로 시작)은 사건 알림이 아니라 따지지 않는다.
    """
    return conn.execute("""SELECT 1 FROM slack_delivery WHERE incident_id = %s AND job_id <> %s
                           AND report_version NOT LIKE 'status:%%' LIMIT 1""",
                        (incident_id, job_id)).fetchone() is not None


def group_alert(previous, start, rule):
    """새 사건 알림을 어느 묶음에 붙일지 정한다(DD-010 결정 5). 표준 라이브러리만 쓴다.

    previous: 같은 자산·역할의 앞선 사건 알림들(사건마다 하나). 원소: {"incident_id", "thread_parent"(머리면 None 또는 자기 자신),
              "reply_broadcast",
              "first_start", "last_end"(관측 시각, epoch 초), "root_closed"(묶음 머리 사건이 종료됐는가)}
    start: 새 사건의 첫 창 시각(epoch 초). rule: {"window_minutes": 60, "realert_minutes": 30}
    반환: (묶음 머리 incident_id 또는 None(새 머리 알림), reply_broadcast)
    """
    groups = {}
    for a in previous:
        root = a["thread_parent"] or a["incident_id"]
        g = groups.setdefault(root, {"last_end": a["last_end"], "notified": None, "closed": a["root_closed"]})
        g["last_end"] = max(g["last_end"], a["last_end"])
        g["closed"] = g["closed"] or a["root_closed"]
        if root == a["incident_id"] or a["reply_broadcast"]:          # 채널에 올라간 알림(머리 또는 재알림)
            g["notified"] = a["first_start"] if g["notified"] is None else max(g["notified"], a["first_start"])
    window = rule["window_minutes"] * 60
    open_groups = [(g["last_end"], root) for root, g in groups.items()
                   if not g["closed"] and start - g["last_end"] <= window]
    if not open_groups:
        return None, False
    root = max(open_groups)[1]
    notified = groups[root]["notified"]
    broadcast = notified is not None and start - notified >= rule["realert_minutes"] * 60
    return root, broadcast


def alert_thread(conn, job_id, incident_id, report_version, rule):
    """이 알림의 (thread_parent, reply_broadcast). 같은 사건의 뒤 알림은 앞 알림의 스레드를 따른다."""
    status = report_version.startswith("status:")
    # 사건의 스레드: 머리 알림의 뒤 알림은 thread_parent가 자기 자신이라, 자기 자신이 아닌 부모가 있으면 답글 사건이다.
    # 기록 시각 순서에 기대지 않는다(같은 트랜잭션 안의 행은 시각이 같다)
    seen, parent = conn.execute("""SELECT count(*), max(NULLIF(thread_parent, incident_id)) FROM slack_delivery
                                   WHERE incident_id = %s AND report_version NOT LIKE 'status:%%'""",
                                (incident_id,)).fetchone()
    if seen:                                    # 이 사건을 이미 알렸다: 그 스레드의 답글(LLM 보고서 추가·상태 변경)
        return parent or incident_id, False
    if status:                                  # 알린 적 없는 사건의 상태 변경: 묶음 없이 그대로
        return None, False
    asset, role, start = conn.execute("""SELECT asset_id, role, extract(epoch FROM first_start) FROM incident
                                         WHERE job_id = %s AND incident_id = %s""", (job_id, incident_id)).fetchone()
    rows = conn.execute("""
        WITH first_alert AS (            -- 사건마다 하나: 자기 자신이 아닌 부모(답글이면), 재알림 여부
            SELECT d.incident_id, max(NULLIF(d.thread_parent, d.incident_id)) AS thread_parent,
                   bool_or(d.reply_broadcast) AS reply_broadcast
            FROM slack_delivery d JOIN incident i USING (job_id, incident_id)
            WHERE i.asset_id = %s AND i.role = %s AND d.report_version NOT LIKE 'status:%%' AND d.incident_id <> %s
            GROUP BY d.incident_id)
        SELECT f.incident_id, f.thread_parent, f.reply_broadcast,
               (SELECT extract(epoch FROM min(first_start)) FROM incident x WHERE x.incident_id = f.incident_id),
               (SELECT extract(epoch FROM max(last_end)) FROM incident x WHERE x.incident_id = f.incident_id),
               EXISTS (SELECT 1 FROM incident_status s WHERE s.incident_id = coalesce(f.thread_parent, f.incident_id)
                       AND s.status = 'closed')
        FROM first_alert f""", (asset, role, incident_id)).fetchall()
    previous = [{"incident_id": r[0], "thread_parent": r[1], "reply_broadcast": r[2], "first_start": float(r[3]),
                 "last_end": float(r[4]), "root_closed": r[5]} for r in rows]
    return group_alert(previous, float(start), rule)


def record_delivery(conn, job_id, incident_id, report_version, payload, config):
    """dry_run: DB에 한 번만 기록하고 파일에 한 줄 덧붙인다. 반환: 새로 기록했으면 True, 이미 있으면 False.

    설정에 grouping이 있으면 알림 묶음(스레드)을 정해 기록한다. 답글이면 payload에 zeekad_thread_parent(머리 사건)와
    Slack 필드 reply_broadcast를 넣는다. 실제 전송 때는 머리 사건 첫 알림의 slack_ts를 thread_ts로 쓴다.
    """
    from psycopg.types.json import Jsonb  # DB 쓸 때만 필요하다(메시지 만들기는 표준 라이브러리만 쓴다)

    if config["mode"] != "dry_run":
        raise NotImplementedError("live 전송은 Slack 토큰이 생기면 붙인다")
    parent, broadcast = None, False
    if config.get("grouping"):
        parent, broadcast = alert_thread(conn, job_id, incident_id, report_version, config["grouping"])
    if parent is not None:
        payload = {**payload, "zeekad_thread_parent": parent, "reply_broadcast": broadcast}
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    row = conn.execute("""INSERT INTO slack_delivery (job_id, incident_id, report_version, mode, payload,
                                                      payload_sha256, status, thread_parent, reply_broadcast)
                          VALUES (%s, %s, %s, 'dry_run', %s, %s, 'recorded', %s, %s)
                          ON CONFLICT DO NOTHING RETURNING created_at""",
                       (job_id, incident_id, report_version, Jsonb(payload), digest, parent, broadcast)).fetchone()
    if row is None:
        return False
    log = PROJECT_ROOT / config["dry_run_log"]
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"job_id": job_id, "incident_id": incident_id, "report_version": report_version,
                            "recorded_at": row[0].isoformat(), "payload": payload}, ensure_ascii=False) + "\n")
    return True


SUMMARY_VERSION = "daily-summary.v1"


def daily_summary(job, counts, unsent, config, max_listed=20):
    """채점 작업(캡처 하루)의 일일 요약. 보내지 않은 사건도 숨기지 않는다(DD-001).

    job: {job_id, capture_id}. counts: {queue, decided, sent}. unsent: [(queue_rank, asset, role)] 판단했지만 보내지 않은 사건.
    """
    listed = "\n".join(f"• {r}위 {escape(a)} ({escape(role)})" for r, a, role in unsent[:max_listed])
    more = f"\n… 외 {len(unsent) - max_listed}건" if len(unsent) > max_listed else ""
    undecided = counts["queue"] - counts["decided"]
    text = (f"[{job['capture_id']}] 일일 요약: 조사 큐 {counts['queue']}건 · 전송 판단 {counts['decided']}건 · "
            f"보냄 {counts['sent']}건 · 보내지 않음 {len(unsent)}건")
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{escape(text)}*"}}]
    if unsent:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*보내지 않은 사건*\n" + listed + more}})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": (
        f"전송 판단을 하지 않은 사건 {undecided}건도 조사 큐에 그대로 있다 · "
        f"전체 큐: {config['api_base_url']}/api/v1/captures/{escape(job['capture_id'])}/queue")}]})
    return {"channel": config["channel"], "text": text, "blocks": blocks}


def record_summary(conn, job_id, payload, config):
    """일일 요약을 한 번만 기록한다(dry_run). 반환: 새로 기록했으면 True."""
    from psycopg.types.json import Jsonb

    if config["mode"] != "dry_run":
        raise NotImplementedError("live 전송은 Slack 토큰이 생기면 붙인다")
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    row = conn.execute("""INSERT INTO slack_summary (job_id, summary_version, mode, payload, payload_sha256, status)
                          VALUES (%s, %s, 'dry_run', %s, %s, 'recorded')
                          ON CONFLICT DO NOTHING RETURNING created_at""",
                       (job_id, SUMMARY_VERSION, Jsonb(payload),
                        hashlib.sha256(body.encode("utf-8")).hexdigest())).fetchone()
    if row is None:
        return False
    log = PROJECT_ROOT / config["dry_run_log"]
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"job_id": job_id, "summary_version": SUMMARY_VERSION, "recorded_at": row[0].isoformat(),
                            "payload": payload}, ensure_ascii=False) + "\n")
    return True


STATUS_LABEL = {"open": "열림", "investigating": "확인 중", "closed": "종료"}
RESOLUTION_LABEL = {"true_positive": "실제 공격", "false_positive": "오탐", "benign": "이상하지만 정상 업무"}


def status_message(incident, to_status, resolution, actor, reason, config):
    """사건 상태가 바뀌었을 때의 후속 알림. 분석가 이름과 이유는 사람이 쓴 글이라 이스케이프한다."""
    label = STATUS_LABEL[to_status] + (f"({RESOLUTION_LABEL[resolution]})" if resolution else "")
    head = f"[{incident['capture_id']}] 조사 큐 {incident['queue_rank']}위 · {incident['asset']} → {label}"
    link = f"{config['api_base_url']}/api/v1/jobs/{incident['job_id']}/incidents/{incident['queue_rank']}"
    return {"channel": config["channel"], "text": head,
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": f"*{escape(head)}*\n"
                                                    f"담당: {escape(actor)} · 이유: {_cut(reason, 300)}"}},
                       {"type": "context", "elements": [{"type": "mrkdwn", "text": f"사건: {link}"}]}]}
