"""사건 근거 요약과 자산 관측을 PostgreSQL에 쓴다(단계 4 5번, DD-010). worker 다음에 돈다.

- 자산 관측: 캡처마다 Zeek kerberos·ntlm 로그 → asset_observation(캡처 단위로 지우고 다시 쓴다).
- 근거 요약: 완료된 채점 작업마다 이벤트 표(Parquet)에서 사건 창의 연결을 모아 incident_evidence에 쓴다.
  작업 하나 = 트랜잭션 하나. 이미 모든 사건의 근거가 있으면 건너뛴다.
예: python scripts/build_evidence.py --set cic synthetic
"""

import argparse
import json
from pathlib import Path
import sys
import time

import pandas as pd
from psycopg.types.json import Jsonb

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets  # noqa: E402
from zeek_ad.db import connect  # noqa: E402
from zeek_ad.evidence import EVENT_COLUMNS, EVIDENCE_VERSION, asset_observations, incident_rows, summarize_incident  # noqa: E402

INPUTS = PROJECT_ROOT / "configs" / "worker" / "inputs.v1.json"


def write_observations(conn, cap, run_dir, is_asset):
    rows = asset_observations(run_dir, cap, is_asset)
    with conn.transaction():
        conn.execute("DELETE FROM asset_observation WHERE capture_id = %s", (cap,))
        with conn.cursor() as cur:
            cur.executemany("""INSERT INTO asset_observation (capture_id, asset_id, kind, value, source_log, observations,
                                                              first_seen, last_seen)
                               VALUES (%(capture_id)s, %(asset_id)s, %(kind)s, %(value)s, %(source_log)s,
                                       %(observations)s, %(first_seen)s, %(last_seen)s)""", rows)
    return len(rows)


def write_evidence(conn, job_id, cap, events_dir):
    n_inc, n_ev = conn.execute("""SELECT (SELECT count(*) FROM incident WHERE job_id = %s),
                                         (SELECT count(*) FROM incident_evidence WHERE job_id = %s
                                          AND evidence_version = %s)""", (job_id, job_id, EVIDENCE_VERSION)).fetchone()
    if n_inc == n_ev:
        return None
    incidents = conn.execute(
        """SELECT i.incident_id, host(i.asset_id), i.role, extract(epoch FROM i.first_start)::bigint,
                  extract(epoch FROM i.last_end)::bigint,
                  array_agg(extract(epoch FROM w.window_start)::bigint ORDER BY w.window_start)
           FROM incident i JOIN incident_window w USING (job_id, incident_id)
           WHERE i.job_id = %s GROUP BY 1, 2, 3, 4, 5""", (job_id,)).fetchall()
    events = pd.read_parquet(Path(events_dir) / "events", columns=EVENT_COLUMNS,
                             filters=[("capture_id", "==", cap)])
    # 사건 창에 든 연결만 남겨 두고 사건마다 고른다.
    events = events[events.window_start.isin({w for *_, ws in incidents for w in ws})]
    with conn.transaction():
        conn.execute("DELETE FROM incident_evidence WHERE job_id = %s", (job_id,))
        with conn.cursor() as cur:
            for incident_id, asset, role, first, last, windows in incidents:
                rows = incident_rows(events, asset, role, windows)
                if rows.empty:
                    raise ValueError(f"{incident_id}: 사건 창에 연결이 없다(이벤트 표와 Gold가 어긋남)")
                ev = summarize_incident(rows, asset, role, first, last)
                cur.execute("""INSERT INTO incident_evidence (job_id, incident_id, evidence_version, connection_count,
                                                               evidence) VALUES (%s, %s, %s, %s, %s)""",
                            (job_id, incident_id, EVIDENCE_VERSION, ev["connection_count"], Jsonb(ev)))
    return len(incidents)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", nargs="+", default=["cic"], dest="sets")
    parser.add_argument("--db", default="zeekad")
    # 실습망 리비전(DD-012)은 scripts/live_recompute.py가 만든 <리비전>/worker-inputs.json을 준다.
    parser.add_argument("--inputs", type=Path, default=INPUTS, help="입력 묶음 정의 파일")
    # 실습망은 configs/assets.lab.v1.json. 기본값은 CIC 설정(기존 동작).
    parser.add_argument("--assets", type=Path, nargs="+", default=[assets.PROJECT_CONFIG])
    args = parser.parse_args()
    inputs = json.loads(args.inputs.read_text(encoding="utf-8"))["sets"]
    networks = assets.load_networks(args.assets)

    def is_asset(ip):
        return assets.is_scored_asset(ip, networks)

    with connect("zeekad_worker", dbname=args.db, autocommit=True) as conn:
        for name in args.sets:
            cfg = inputs[name]
            for cap, run_dir in cfg["zeek_run_dirs"].items():
                n = write_observations(conn, cap, PROJECT_ROOT / run_dir, is_asset)
                print(f"{cap}: asset observations {n}", flush=True)
            jobs = conn.execute("""SELECT job_id, capture_id FROM scoring_job
                                   WHERE status = 'succeeded' AND capture_id = ANY(%s) ORDER BY job_id""",
                                (cfg["captures"],)).fetchall()
            for job_id, cap in jobs:
                began = time.perf_counter()
                n = write_evidence(conn, job_id, cap, PROJECT_ROOT / cfg["events_dir"])
                print(f"{cap}: job {job_id} evidence {'이미 있음, 건너뜀' if n is None else f'{n}건'} "
                      f"{time.perf_counter() - began:.0f}s", flush=True)


if __name__ == "__main__":
    main()
