"""추론 worker 장애 복구 시험(설계 7.2절, 단계 4). 시험 DB(zeekad_test)에서 화요일(cic17-tue) 작업 하나로 한다.

시나리오(각각 표를 비우고 시작한다):
A. 창 점수를 쓴 직후 프로세스 종료 → 결과 0행, 작업 running → 다시 실행하면 이어받아 완료
B. commit 직전 프로세스 종료 → A와 같아야 한다
C. commit 직후 프로세스 종료 → 결과 전부, 작업 succeeded → 다시 실행하면 건너뜀(중복 0)
D. 쓰는 중 예외 → 롤백, 작업 failed와 오류 문구 → 다시 실행하면 완료
E. worker 두 개를 동시에 실행 → 한쪽만 쓰고 다른 쪽은 쓰지 않는다
완료 결과는 운영 DB(zeekad)의 같은 작업과 사건 순서·창 점수 수가 같아야 한다.
"""

import os
from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect  # noqa: E402

CAPTURE = "cic17-tue"
TEST_DB = "zeekad_test"
WORKER = [sys.executable, str(PROJECT_ROOT / "scripts" / "run_worker.py"), "--set", "cic", "--captures", CAPTURE,
          "--db", TEST_DB]


def run_worker(fault=None, wait=True):
    env = {**os.environ, "MLFLOW_DISABLE_AGENT_HINT": "1"}
    env.pop("ZEEKAD_FAULT", None)
    if fault:
        env["ZEEKAD_FAULT"] = fault
    p = subprocess.Popen(WORKER, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return finish(p) if wait else p


def finish(p):
    out, _ = p.communicate()
    lines = [x for x in out.splitlines() if x.startswith((CAPTURE, "FAULT", "RuntimeError"))]
    return p.returncode, lines


def snapshot(dbname):
    """작업 상태, 행 수, 사건 순서(순위·ID·뽑은 모델·겹친 모델)."""
    with connect("zeekad_owner", dbname=dbname) as conn:
        jobs = conn.execute("SELECT job_id, status, error FROM scoring_job WHERE capture_id = %s", (CAPTURE,)).fetchall()
        ids = [j[0] for j in jobs]
        count = {t: conn.execute(f"SELECT count(*) FROM {t} WHERE job_id = ANY(%s)", (ids,)).fetchone()[0]
                 for t in ["window_score", "incident", "incident_window"]}
        queue = conn.execute("""SELECT queue_rank, incident_id, picked_by, also_flagged_by FROM incident
                                WHERE job_id = ANY(%s) ORDER BY queue_rank""", (ids,)).fetchall()
    return {"jobs": [(s, (e or "")[:60]) for _, s, e in jobs], "count": count, "queue": queue}


def reset():
    with connect("zeekad_owner", dbname=TEST_DB) as conn:
        conn.execute("TRUNCATE scoring_job, model_bundle CASCADE")


def main():
    reference = snapshot("zeekad")
    if reference["jobs"] != [("succeeded", "")]:
        sys.exit("운영 DB에 비교할 완료 작업이 없다")
    complete = lambda s: s["jobs"] == [("succeeded", "")] and s["count"] == reference["count"] \
        and s["queue"] == reference["queue"]  # noqa: E731
    empty = lambda s: all(v == 0 for v in s["count"].values())  # noqa: E731
    results = []

    def check(name, ok, detail):
        results.append((name, ok))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", flush=True)

    for label, point in [("A 쓰는 중 종료", "mid_write"), ("B commit 직전 종료", "before_commit")]:
        reset()
        code, lines = run_worker(point)
        s = snapshot(TEST_DB)
        check(f"{label} → 결과 없음", code == 17 and s["jobs"] == [("running", "")] and empty(s),
              f"exit={code} jobs={s['jobs']} rows={s['count']}")
        code, lines = run_worker()
        s = snapshot(TEST_DB)
        check(f"{label} → 재실행 완료", code == 0 and complete(s) and any("(resume)" in x for x in lines),
              f"exit={code} {lines[-1:]} rows={s['count']}")

    reset()
    code, lines = run_worker("after_commit")
    s = snapshot(TEST_DB)
    check("C commit 직후 종료 → 결과 전부", code == 17 and complete(s), f"exit={code} jobs={s['jobs']} rows={s['count']}")
    code, lines = run_worker()
    s2 = snapshot(TEST_DB)
    check("C → 재실행은 건너뜀(중복 0)", code == 0 and any("이미 완료" in x for x in lines) and s2 == s,
          f"{lines[-1:]} rows={s2['count']}")

    reset()
    code, lines = run_worker("raise_mid_write")
    s = snapshot(TEST_DB)
    check("D 쓰는 중 예외 → 롤백·failed 기록", code != 0 and s["jobs"][0][0] == "failed" and "시험용 예외" in s["jobs"][0][1]
          and empty(s), f"exit={code} jobs={s['jobs']} rows={s['count']}")
    code, lines = run_worker()
    s = snapshot(TEST_DB)
    check("D → 재실행 완료", code == 0 and complete(s), f"{lines[-1:]} rows={s['count']}")

    reset()
    procs = [run_worker(wait=False) for _ in range(2)]
    outs = [finish(p) for p in procs]
    s = snapshot(TEST_DB)
    skipped = sum(any("먼저 끝냄" in x or "이미 완료" in x for x in lines) for _, lines in outs)
    check("E 동시 실행 → 한쪽만 씀", all(c == 0 for c, _ in outs) and complete(s) and skipped == 1,
          f"{[lines[-1:] for _, lines in outs]} rows={s['count']}")

    reset()
    print(f"{sum(ok for _, ok in results)}/{len(results)} 통과")
    if not all(ok for _, ok in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
