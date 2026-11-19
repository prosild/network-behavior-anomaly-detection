"""근거 API와 대시보드 계약을 확인한다(단계 4 5번). 서버를 띄우지 않고 FastAPI TestClient로 부른다.

1. API: 엔드포인트 응답 형식, 입력 검증(잘못된 capture_id·rank는 422/404), 수요일 1위 사건의 근거.
2. 권한: dashboard_ro는 dashboard 뷰만 읽고 원래 표는 못 읽는다. zeekad_api는 쓰지 못한다.
"""

from pathlib import Path
import sys

from fastapi.testclient import TestClient
import psycopg

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.api import app  # noqa: E402
from zeek_ad.db import connect  # noqa: E402

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def denied(role, sql):
    try:
        with connect(role) as conn:
            conn.execute(sql)
        return False
    except psycopg.errors.InsufficientPrivilege:
        return True


def main():
    c = TestClient(app)
    check("health", c.get("/health").json() == {"status": "ok"})
    jobs = c.get("/api/v1/jobs").json()
    check("jobs", len(jobs) == 8 and all(j["status"] == "succeeded" for j in jobs), f"{len(jobs)} jobs")
    q = c.get("/api/v1/captures/cic17-wed/queue", params={"limit": 3}).json()
    check("queue", len(q["incidents"]) == 3 and q["incidents"][0]["zeekad_rank"] == 1, str(q["incidents"][0]["host"]))
    d = c.get(f"/api/v1/jobs/{q['zeekad_job_id']}/incidents/1").json()
    models = {m["zeekad_model"]: m for m in d["detection"]["models"]}
    check("incident detail", set(models) == {"tgn_recon", "tail_rarity_v2", "transformer_v2"}
          and models[d["detection"]["zeekad_picked_by"]]["above_threshold"]
          and d["evidence"]["connection_count"] > 0 and d["evidence"]["version"] == "evidence.v1",
          f"picked={d['detection']['zeekad_picked_by']} conns={d['evidence']['connection_count']}")
    check("asset names from Zeek", any(n["zeekad_source_log"] == "kerberos.log" for n in d["zeekad_asset_observations"]),
          str([n["zeekad_name"] for n in d["zeekad_asset_observations"]]))
    check("bad capture_id 422", c.get("/api/v1/captures/x'%20or%201=1/queue").status_code in (404, 422))
    check("limit bound 422", c.get("/api/v1/captures/cic17-wed/queue", params={"limit": 1000}).status_code == 422)
    check("unknown capture 404", c.get("/api/v1/captures/cic17-sun/queue").status_code == 404)
    check("unknown rank 404", c.get(f"/api/v1/jobs/{q['zeekad_job_id']}/incidents/99999").status_code == 404)

    with connect("dashboard_ro") as conn:
        n = conn.execute("SELECT count(*) FROM dashboard.incident_queue").fetchone()[0]
    check("dashboard_ro reads views", n == 2128, f"{n} rows")
    check("dashboard_ro cannot read tables", denied("dashboard_ro", "SELECT 1 FROM zeekad.incident LIMIT 1"))
    check("zeekad_api cannot write", denied("zeekad_api", "DELETE FROM zeekad.incident_evidence"))
    print(f"{sum(results)}/{len(results)} 통과")
    if not all(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
