"""단계 5b: DB의 전송 판단이 would_send인 사건마다 Slack 메시지를 만들고 기록한다(dry-run, DD-001).

입력: DB(incident, agent_report, send_decision), configs/agent/slack.v1.json.
- --preview: 기록하지 않고 메시지 JSON만 출력한다(사건 하나를 --incident로 고른다).
- 기본: would_send인 모든 사건을 기록한다. 같은 (사건, 보고서 버전)은 한 번만 기록된다.
예: python scripts/run_slack.py --preview --incident 'cic17-fri|192.168.10.50|responder|1499447700'
"""

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect  # noqa: E402
from zeek_ad.slack import daily_summary, incident_message, record_delivery, record_summary  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "agent" / "slack.v1.json"
QUERY = """SELECT i.job_id, i.incident_id, j.capture_id, i.queue_rank, host(i.asset_id), i.role, i.first_start,
                  i.last_end, i.picked_by, i.also_flagged_by, r.report, r.report_kind, r.report_version,
                  d.policy, d.llm_choice, d.decision_model, d.would_send
           FROM send_decision d
           JOIN incident i USING (job_id, incident_id)
           JOIN scoring_job j USING (job_id)
           JOIN agent_report r USING (job_id, incident_id)"""


def rows(conn, incident=None):
    sql, params = QUERY, ()
    if incident:
        sql, params = QUERY + " WHERE i.incident_id = %s", (incident,)
    for r in conn.execute(sql + " ORDER BY j.capture_id, i.queue_rank", params).fetchall():
        (job, iid, cap, rank, asset, role, t0, t1, picked, also, report, kind, version, policy, llm, dm, send) = r
        yield ({"job_id": job, "incident_id": iid, "capture_id": cap, "queue_rank": rank, "asset": asset,
                "role": role, "first_start": t0, "last_end": t1, "picked_by": picked, "also_flagged_by": also},
               report, kind, version, {"policy": policy, "llm_choice": llm, "decision_model": dm}, send)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preview", action="store_true")
    parser.add_argument("--incident")
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    with connect("zeekad_worker") as conn:
        new = old = skipped = 0
        for inc, report, kind, version, decision, send in rows(conn, args.incident):
            msg = incident_message(inc, report, kind, decision, config)
            if args.preview:
                print(f"would_send={send}")
                print(json.dumps(msg, ensure_ascii=False, indent=1))
                continue
            if not send:
                skipped += 1
                continue
            if record_delivery(conn, inc["job_id"], inc["incident_id"], version, msg, config):
                new += 1
            else:
                old += 1
        if not args.preview:
            print(f"사건 알림: 새로 기록 {new}, 이미 기록됨 {old}, 보내지 않음 {skipped} (mode={config['mode']})")
        if args.incident:
            return
        # 일일 요약: 전송 판단이 있는 채점 작업마다 하나
        jobs = conn.execute("""SELECT DISTINCT j.job_id, j.capture_id FROM send_decision d JOIN scoring_job j USING (job_id)
                               ORDER BY j.capture_id""").fetchall()
        for job_id, cap in jobs:
            queue = conn.execute("SELECT count(*) FROM incident WHERE job_id = %s", (job_id,)).fetchone()[0]
            dec = conn.execute("""SELECT d.would_send, i.queue_rank, host(i.asset_id), i.role FROM send_decision d
                                  JOIN incident i USING (job_id, incident_id) WHERE d.job_id = %s
                                  ORDER BY i.queue_rank""", (job_id,)).fetchall()
            unsent = [(r, a, role) for send, r, a, role in dec if not send]
            msg = daily_summary({"job_id": job_id, "capture_id": cap},
                                {"queue": queue, "decided": len(dec), "sent": sum(1 for d in dec if d[0])},
                                unsent, config)
            if args.preview:
                print(json.dumps(msg, ensure_ascii=False, indent=1))
            else:
                print(f"일일 요약 {cap}: {'새로 기록' if record_summary(conn, job_id, msg, config) else '이미 기록됨'}"
                      f" — {msg['text']}")


if __name__ == "__main__":
    main()
