"""근거 조회 API(FastAPI, 단계 4 5번, DD-010). 읽기 전용 계정(zeekad_api)으로 PostgreSQL만 읽는다.

실행: python scripts/run_api.py → http://127.0.0.1:8000/docs (OpenAPI 문서)
- GET /health
- GET /api/v1/jobs                                  채점 작업 목록
- GET /api/v1/captures/{capture_id}/queue?limit=10   그 캡처의 최신 완료 작업의 결합 큐
- GET /api/v1/jobs/{job_id}/incidents/{rank}         사건 하나의 근거(모델 점수, 연결 요약, 관측된 자산 이름)
응답 필드는 ECS 이름이다. 프로젝트 고유 값은 zeekad_ 접두사다.
"""

from datetime import datetime
from typing import Annotated

from fastapi import FastAPI, HTTPException, Path, Query
import psycopg

from zeek_ad.db import connect

app = FastAPI(title="zeek_AD 근거 조회 API", version="1.0.0",
              description="결합 v1(DD-009) 조사 큐와 사건 근거. 점수는 정상 대비 이상함이며 공격 확정이 아니다.")
CaptureId = Annotated[str, Path(pattern=r"^[a-z0-9][a-z0-9-]{1,31}$")]


def query(sql, params=()):
    # 요청마다 읽기 전용 계정으로 접속한다. 값은 항상 파라미터 바인딩으로 넘긴다(SQL 인젝션 방지).
    try:
        with connect("zeekad_api") as conn:
            cur = conn.execute(sql, params)
            cols = [c.name for c in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    except psycopg.OperationalError:
        # 내부 오류 문구(접속 정보 등)를 응답에 내보내지 않는다.
        raise HTTPException(status_code=503, detail="database unavailable")


def ts(value):
    return value.isoformat().replace("+00:00", "Z") if isinstance(value, datetime) else value


@app.get("/health")
def health():
    query("SELECT 1 AS ok")
    return {"status": "ok"}


@app.get("/api/v1/jobs")
def jobs():
    rows = query("SELECT * FROM dashboard.scoring_jobs ORDER BY job_id")
    return [{**r, "started_at": ts(r["started_at"]), "finished_at": ts(r["finished_at"])} for r in rows]


@app.get("/api/v1/captures/{capture_id}/queue")
def capture_queue(capture_id: CaptureId, limit: Annotated[int, Query(ge=1, le=200)] = 10):
    job = query("""SELECT max(job_id) AS job_id FROM zeekad.scoring_job
                   WHERE capture_id = %s AND status = 'succeeded'""", (capture_id,))[0]["job_id"]
    if job is None:
        raise HTTPException(status_code=404, detail="no completed job for capture")
    rows = query("""SELECT * FROM dashboard.incident_queue WHERE job_id = %s ORDER BY queue_rank LIMIT %s""",
                 (job, limit))
    return {"zeekad_job_id": job, "capture_id": capture_id, "bundle_id": rows[0]["bundle_id"] if rows else None,
            "incidents": [{"zeekad_rank": r["queue_rank"], "zeekad_incident_id": r["incident_id"],
                           "host": {"ip": r["host_ip"], "name": r["host_name"] or []}, "zeekad_role": r["zeekad_role"],
                           "event": {"start": ts(r["event_start"]), "end": ts(r["event_end"])},
                           "zeekad_picked_by": r["zeekad_picked_by"],
                           "zeekad_also_flagged_by": r["zeekad_also_flagged_by"],
                           "connection_count": r["connection_count"]} for r in rows]}


@app.get("/api/v1/jobs/{job_id}/incidents/{rank}")
def incident(job_id: Annotated[int, Path(ge=1)], rank: Annotated[int, Path(ge=1)]):
    rows = query("""SELECT q.*, i.model_score, e.evidence
                    FROM dashboard.incident_queue q
                    JOIN zeekad.incident i USING (job_id, incident_id)
                    LEFT JOIN zeekad.incident_evidence e USING (job_id, incident_id)
                    WHERE q.job_id = %s AND q.queue_rank = %s""", (job_id, rank))
    if not rows:
        raise HTTPException(status_code=404, detail="incident not found")
    r = rows[0]
    thresholds = query("SELECT thresholds FROM dashboard.model_bundles WHERE bundle_id = %s",
                       (r["bundle_id"],))[0]["thresholds"]
    scores = query("""SELECT zeekad_model, max_score, candidate_windows, windows FROM dashboard.incident_model_scores
                      WHERE job_id = %s AND incident_id = %s ORDER BY zeekad_model""", (job_id, r["incident_id"]))
    names = query("""SELECT zeekad_name_kind, zeekad_name, zeekad_source_log, observations, first_seen, last_seen
                     FROM dashboard.asset_names WHERE capture_id = %s AND host_ip = %s
                     ORDER BY zeekad_name_kind, zeekad_name""", (r["capture_id"], r["host_ip"]))
    return {
        "zeekad_job_id": job_id, "zeekad_rank": rank, "zeekad_incident_id": r["incident_id"],
        "capture_id": r["capture_id"], "bundle_id": r["bundle_id"],
        "host": {"ip": r["host_ip"], "name": r["host_name"] or []}, "zeekad_role": r["zeekad_role"],
        "event": {"start": ts(r["event_start"]), "end": ts(r["event_end"])},
        "detection": {
            "zeekad_picked_by": r["zeekad_picked_by"], "zeekad_also_flagged_by": r["zeekad_also_flagged_by"],
            "zeekad_picked_model_score": r["model_score"],
            "models": [{**s, "threshold": thresholds.get(s["zeekad_model"]),
                        "above_threshold": s["max_score"] >= thresholds.get(s["zeekad_model"], float("inf"))}
                       for s in scores],
        },
        "zeekad_asset_observations": [{**n, "first_seen": ts(n["first_seen"]), "last_seen": ts(n["last_seen"])}
                                      for n in names],
        "evidence": r["evidence"],
    }
