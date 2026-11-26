"""종료한 사건 다시 열기(dashboard.reopen_incident, migration 018·DD-022)를 실제 DB에서 확인한다. DB에 아무것도 남기지 않는다.

예: python scripts/verify_incident_reopen.py                 (운영 DB zeekad)
    python scripts/verify_incident_reopen.py --db zeekad_test

설계: 재개는 별도 함수 reopen_incident(대시보드 dashboard_rw만 실행)로만 한다. transition_incident(012 정의)는 앞으로만 가므로
오래된 화면의 "분석 시작"(closed 사건에 p_to = 'investigating')은 거부되어야 한다. 이것이 이 설계의 핵심 확인이다.
하는 일(사건 하나: 캡처의 최신 작업에서 상태 행이 없는 사건 우선)
1. 카탈로그: 두 함수의 개수·SECURITY DEFINER·search_path·소유자·반환형·실행 권한.
   reopen_incident(인자 5개, 마지막은 기대 결론 p_expected_resolution)가 없으면 "migration 018이 적용되지 않았다"로 종료 코드 2.
2. zeekad_worker 트랜잭션(파이프라인 계정): transition_incident의 거부(closed → investigating 포함), worker의 reopen_incident
   실행 거부(42501), 그리고 agent_graph.reopened_after_review 질의를 실제로 실행해 문법·권한 오류가 없는지 본다.
3. 재개 호출 계정 트랜잭션: dashboard_rw(실제로 쓸 계정)로 접속할 수 있으면 그 계정, 아니면 zeekad_owner.
   함수 호출만으로 open → investigating → closed → reopen_incident → closed(다른 결론)와 reopen_incident의 거부를 본다.
   dashboard_rw는 표·뷰를 읽을 수 없어 결과 값 확인은 4에서 한다.
4. zeekad_owner 트랜잭션: 같은 흐름을 다시 하며 상태 행·이력·뷰(dashboard.incident_status·latest_incident_queue)를 읽고,
   열림 사건의 재개 거부 뒤 상태 행이 생기지 않는지, 기대 결론이 다르거나 엉뚱한 값이면 거부되고 상태가 그대로인지,
   같으면 다시 열리는지, reopened_after_review가 검토 결정 시각과 재개 시각의 앞뒤에 따라
   True·False가 되는지(SAVEPOINT 안에서 analyst_review 행을 넣었다 되돌림) 본다.
   worker 트랜잭션에서는 재개를 만들 수 없어(worker에는 reopen_incident 권한이 없다) 이 의미 확인은 소유자로 한다.
5. 새 접속으로 그 사건의 상태 행·이력·검토 행이 시작 전과 같은지 본다(남긴 것 없음).
트랜잭션은 모두 끝에 ROLLBACK한다. 거부 확인은 SAVEPOINT로 되돌려 같은 트랜잭션을 이어 쓴다.
고른 사건의 시작 상태 때문에 할 수 없는 확인은 조용히 넘기지 않고 [SKIP]으로 출력한다.
사건 ID에는 실제 IP가 있어 출력에는 캡처·작업·큐 순위만 쓴다. DB 오류는 SQLSTATE와 요약 문장만 찍고, 사건 ID·IP 모양은 가린다.
종료 코드: 0(모두 통과), 1(실패 또는 DB 오류), 2(migration 018이 적용되지 않았다)
참고: 이력 표의 번호(history_id, IDENTITY)는 ROLLBACK해도 되돌아가지 않아 번호에 빈칸이 생긴다. 행은 남지 않는다.
검증하는 동안 그 사건의 상태 행을 잠가(FOR UPDATE) 대시보드가 같은 사건을 바꾸면 끝날 때까지(1초 안팎) 기다린다.
"""

import argparse
from pathlib import Path
import re
import sys

import psycopg
from psycopg import pq

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.agent_graph import reopened_after_review  # noqa: E402  (apply_status가 쓰는 질의 그대로)
from zeek_ad.db import connect, load_env  # noqa: E402

TRANSITION = "dashboard.transition_incident(bigint,text,text,text,text,text)"
REOPEN = "dashboard.reopen_incident(bigint,text,text,text,text)"
# pg_get_function_arguments 표기. 기본값은 판에 따라 NULL 또는 NULL::text로 나와 비교 전에 맞춘다
REOPEN_ARGS = "p_job bigint, p_incident text, p_actor text, p_reason text, p_expected_resolution text DEFAULT NULL"
ACTOR = "verify_incident_reopen"
REJECT_REASON = "검증: 거부되어야 하는 호출"
REOPEN_REASON = "검증: 종료한 사건 다시 열기"
NO_SUCH_INCIDENT = "verify-reopen|no-such-incident"
RESOLUTIONS = ["true_positive", "false_positive", "benign"]
INCIDENT_ID_SHAPE = re.compile(r"[^\s|]+\|[^\s|]+\|[^\s|]+\|\d+")
IPV4_SHAPE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# 캡처마다 가장 최근 성공 작업의 사건(= latest_incident_queue에 나오는 사건). 상태 행이 없는 사건, 그다음 열림 순서.
PICK = """WITH latest AS (
              SELECT DISTINCT ON (capture_id) capture_id, job_id FROM scoring_job
              WHERE status = 'succeeded' ORDER BY capture_id, job_id DESC)
          SELECT i.job_id, i.incident_id, l.capture_id, i.queue_rank, coalesce(s.status, 'open')
          FROM incident i JOIN latest l ON l.job_id = i.job_id
          LEFT JOIN incident_status s ON s.incident_id = i.incident_id
          ORDER BY (s.incident_id IS NOT NULL), array_position(ARRAY['open', 'investigating', 'closed'], s.status),
                   i.job_id DESC, i.queue_rank
          LIMIT 1"""


def mask(text):
    """출력에 실제 IP가 나오지 않게 사건 ID 모양과 IPv4 모양을 가린다."""
    return IPV4_SHAPE.sub("<IP>", INCIDENT_ID_SHAPE.sub("<사건 ID>", text or ""))


def summary(e):
    """DB 오류 요약: SQLSTATE와 첫 문장만(DETAIL·traceback은 찍지 않는다)."""
    first = getattr(e, "diag", None) and e.diag.message_primary
    return f"SQLSTATE {e.sqlstate} {mask(first or type(e).__name__)}"


class Checks:
    def __init__(self):
        self.results = []

    def check(self, name, ok, detail=""):
        self.results.append(bool(ok))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f": {mask(str(detail))}" if detail != "" else ""), flush=True)

    def skip(self, name, why):
        print(f"[SKIP] {name}: {why}", flush=True)


def transition(conn, job, incident, to, reason, resolution=None, actor=ACTOR):
    return conn.execute("SELECT dashboard.transition_incident(%s, %s, %s, %s, %s, %s)",
                        (job, incident, to, actor, reason, resolution)).fetchone()[0]


def reopen(conn, job, incident, reason=REOPEN_REASON, actor=ACTOR, expected=None):
    """expected: 화면이 보고 있던 종료 결론(p_expected_resolution). None이면 상태만 본다."""
    return conn.execute("SELECT dashboard.reopen_incident(%s, %s, %s, %s, %s)",
                        (job, incident, actor, reason, expected)).fetchone()[0]


def other_resolution(resolution):
    """지금 결론과 다른 결론 하나(기대 결론이 어긋난 오래된 화면을 흉내 낸다)."""
    return next(r for r in RESOLUTIONS if r != resolution)


def status_row(conn, incident):
    """상태 행 (status, resolution, updated_by, last_job_id). 행이 없으면 None."""
    return conn.execute("""SELECT status, resolution, updated_by, last_job_id FROM incident_status
                           WHERE incident_id = %s""", (incident,)).fetchone()


def snapshot(conn, job, incident):
    """남긴 것이 없는지 비교할 값: 상태 행 전체, 이력 (행 수, 마지막 번호), 검토 행."""
    row = conn.execute("""SELECT status, resolution, updated_at, updated_by, last_job_id FROM incident_status
                          WHERE incident_id = %s""", (incident,)).fetchone()
    history = conn.execute("""SELECT count(*), coalesce(max(history_id), 0) FROM incident_status_history
                              WHERE incident_id = %s""", (incident,)).fetchone()
    review = conn.execute("""SELECT action, analyst, note, decided_at, resumed_at, resume_error FROM analyst_review
                             WHERE job_id = %s AND incident_id = %s""", (job, incident)).fetchone()
    return row, tuple(history), review


def expect_error(conn, checks, name, want, call):
    """거부되어야 하는 호출. SAVEPOINT로 감싸 거부(또는 잘못 받아들인 변경)를 되돌리고 트랜잭션을 이어 쓴다."""
    conn.execute("SAVEPOINT verify_reject")
    try:
        got = call()
    except psycopg.Error as e:
        conn.execute("ROLLBACK TO SAVEPOINT verify_reject")
        checks.check(f"거부: {name}", e.sqlstate == want, f"기대 {want}, {summary(e)}")
    else:
        conn.execute("ROLLBACK TO SAVEPOINT verify_reject")      # 받아들였으면 되돌려 다음 확인에 영향이 없게 한다
        checks.check(f"거부: {name}", False, f"받아들여졌다(반환 {got})")
    conn.execute("RELEASE SAVEPOINT verify_reject")


def in_transaction(dbname, role, work):
    """트랜잭션 하나에서 work(conn)를 실행하고, 성공·실패와 상관없이 끝에 ROLLBACK한다."""
    conn = connect(role, dbname=dbname)              # autocommit=False: 첫 문장 앞에 BEGIN이 나간다
    try:
        conn.execute("SET LOCAL lock_timeout = '5s'")  # 대시보드가 같은 사건을 잡고 있으면 오래 기다리지 않는다
        if conn.info.transaction_status != pq.TransactionStatus.INTRANS:
            raise RuntimeError("트랜잭션이 열리지 않았다. 변경이 바로 반영될 수 있어 멈춘다")
        work(conn)
    finally:
        conn.rollback()
        conn.close()


FUNCTION_INFO = """SELECT p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner), pg_get_function_result(p.oid),
                          pg_get_function_arguments(p.oid),
                          has_function_privilege('dashboard_rw', p.oid, 'EXECUTE'),
                          has_function_privilege('zeekad_worker', p.oid, 'EXECUTE'),
                          has_function_privilege('dashboard_ro', p.oid, 'EXECUTE'),
                          has_function_privilege('zeekad_api', p.oid, 'EXECUTE'),
                          EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                                  WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')
                   FROM pg_proc p WHERE p.oid = to_regprocedure(%s)"""


def check_functions(dbname, checks):
    """두 함수의 속성과 실행 권한. reopen_incident가 없으면 False(018 미적용)."""
    with connect("zeekad_worker", dbname=dbname, autocommit=True) as conn:
        infos = {}
        for name, signature, runners in [("transition_incident", TRANSITION, {"dashboard_rw", "zeekad_worker"}),
                                         ("reopen_incident", REOPEN, {"dashboard_rw"})]:
            count = conn.execute("""SELECT count(*) FROM pg_proc
                                    WHERE proname = %s AND pronamespace = 'dashboard'::regnamespace""",
                                 (name,)).fetchone()[0]
            infos[name] = (count, conn.execute(FUNCTION_INFO, (signature,)).fetchone(), runners)
    if infos["reopen_incident"][1] is None:
        return False
    for name, (count, row, runners) in infos.items():
        checks.check(f"{name}: 같은 이름의 함수는 하나", count == 1 and row is not None, f"{count}개")
        if row is None:
            continue
        secdef, config, owner, result, args, rw, worker, ro, api, public = row
        paths = [c.replace(" ", "") for c in (config or []) if c.startswith("search_path=")]
        checks.check(f"{name}: SECURITY DEFINER, search_path 고정, 소유자 zeekad_owner, 반환 text",
                     secdef and paths == ["search_path=zeekad,pg_temp"] and owner == "zeekad_owner" and result == "text",
                     f"secdef={secdef} config={config} owner={owner} result={result}")
        if name == "reopen_incident":
            checks.check("reopen_incident: 인자 5개 서명(마지막은 기대 결론, 기본 NULL)",
                         args.replace("NULL::text", "NULL") == REOPEN_ARGS, args)
        got = {"dashboard_rw": rw, "zeekad_worker": worker, "dashboard_ro": ro, "zeekad_api": api, "PUBLIC": public}
        want = {k: k in runners for k in got}
        checks.check(f"{name}: 실행 권한은 {'·'.join(sorted(runners))}만", got == want,
                     " ".join(f"{k}={v}" for k, v in got.items()))
    return True


def advance(conn, job, incident, start, record=None):
    """시작 상태에서 transition_incident로 종료(true_positive)까지 간다. record(이전, 다음, 결론, 왜)에 성공한 전이를 남긴다."""
    plan = [("open", "investigating", None, "검증: 확인 시작"), ("investigating", "closed", "true_positive", "검증: 첫 종료")]
    for frm, to, resolution, reason in plan[{"open": 0, "investigating": 1, "closed": 2}[start]:]:
        transition(conn, job, incident, to, reason, resolution)
        if record is not None:
            record.append((frm, to, resolution, reason))


def worker_part(conn, checks, job, incident, start):
    """zeekad_worker: transition_incident의 거부(핵심: closed → investigating), reopen_incident 권한 없음, 질의 실행."""
    p = "[zeekad_worker] "
    if start == "open":
        expect_error(conn, checks, p + "transition open → closed(건너뛰기)", "22023",
                     lambda: transition(conn, job, incident, "closed", REJECT_REASON, "benign"))
        transition(conn, job, incident, "investigating", "검증: 확인 시작")
    else:
        checks.skip(p + "거부: transition open → closed(건너뛰기)", f"고른 사건이 이미 {start}이다")
    if start in ("open", "investigating"):
        expect_error(conn, checks, p + "transition investigating → open", "22023",
                     lambda: transition(conn, job, incident, "open", REJECT_REASON))
        transition(conn, job, incident, "closed", "검증: 첫 종료", "true_positive")
    else:
        checks.skip(p + "거부: transition investigating → open", f"고른 사건이 이미 {start}이다")
    expect_error(conn, checks, p + "transition closed → investigating(오래된 화면의 분석 시작, 설계 핵심)", "22023",
                 lambda: transition(conn, job, incident, "investigating", REJECT_REASON))
    expect_error(conn, checks, p + "transition closed → open", "22023",
                 lambda: transition(conn, job, incident, "open", REJECT_REASON))
    expect_error(conn, checks, p + "transition closed → closed", "22023",
                 lambda: transition(conn, job, incident, "closed", REJECT_REASON, "benign"))
    expect_error(conn, checks, p + "reopen_incident(worker에는 실행 권한이 없다)", "42501",
                 lambda: reopen(conn, job, incident))
    value = reopened_after_review(conn, job, incident)
    checks.check(p + "reopened_after_review 질의가 문법·권한 오류 없이 실행된다", isinstance(value, bool),
                 f"값 {value}(이 트랜잭션에는 재개가 없다. 참·거짓의 뜻은 소유자 트랜잭션에서 확인)")


def caller_part(conn, checks, job, incident, start, role):
    """재개 호출 계정(dashboard_rw 또는 소유자): 함수 호출만으로 재개 흐름과 reopen_incident의 거부를 본다."""
    p = f"[{role}] "
    if start == "open":
        expect_error(conn, checks, p + "reopen_incident: 열림 사건", "22023", lambda: reopen(conn, job, incident))
        transition(conn, job, incident, "investigating", "검증: 확인 시작")
    else:
        checks.skip(p + "거부: reopen_incident: 열림 사건", f"고른 사건이 이미 {start}이다")
    if start in ("open", "investigating"):
        expect_error(conn, checks, p + "reopen_incident: 확인 중 사건", "22023", lambda: reopen(conn, job, incident))
        transition(conn, job, incident, "closed", "검증: 첫 종료", "true_positive")
        # 이 계정은 표를 읽지 못한다. 결론을 아는 경우(여기서 true_positive로 종료)만 어긋난 기대 결론을 본다
        expect_error(conn, checks, p + "reopen_incident: 기대 결론이 지금 결론과 다름", "22023",
                     lambda: reopen(conn, job, incident, expected=other_resolution("true_positive")))
    else:
        checks.skip(p + "거부: reopen_incident: 확인 중 사건", "고른 사건이 이미 closed다(아래 '이미 다시 연 사건'이 같은 경우)")
        checks.skip(p + "거부: reopen_incident: 기대 결론이 지금 결론과 다름",
                    "이 계정은 결론을 읽을 수 없다(소유자 트랜잭션에서 확인)")
    expect_error(conn, checks, p + "reopen_incident: 기대 결론이 세 값이 아님", "22023",
                 lambda: reopen(conn, job, incident, expected="unknown"))
    expect_error(conn, checks, p + "transition closed → investigating(오래된 화면의 분석 시작, 설계 핵심)", "22023",
                 lambda: transition(conn, job, incident, "investigating", REJECT_REASON))
    expect_error(conn, checks, p + "reopen_incident: 사유가 빈 호출", "22023",
                 lambda: reopen(conn, job, incident, reason="  "))
    expect_error(conn, checks, p + "reopen_incident: 행위자가 빈 호출", "22023",
                 lambda: reopen(conn, job, incident, actor=""))
    expect_error(conn, checks, p + "reopen_incident: 없는 사건 ID", "02000",
                 lambda: reopen(conn, job, NO_SUCH_INCIDENT))
    got = reopen(conn, job, incident)
    checks.check(p + "reopen_incident: closed → investigating(기대 결론 NULL이면 상태만 본다)", got == "investigating",
                 f"반환 {got}")
    expect_error(conn, checks, p + "reopen_incident: 이미 다시 연 사건(확인 중)", "22023",
                 lambda: reopen(conn, job, incident))
    got = transition(conn, job, incident, "closed", "검증: 다시 종료", "benign")
    checks.check(p + "transition: 다시 연 사건을 다시 종료", got == "closed", f"반환 {got}")


def review_semantics(conn, checks, job, incident):
    """재개 뒤(소유자 트랜잭션): reopened_after_review가 결정 시각과 재개 시각의 앞뒤에 따라 맞는 값을 내는가."""
    reopened_at = conn.execute("""SELECT max(changed_at) FROM incident_status_history
                                  WHERE incident_id = %s AND from_status = 'closed' AND to_status = 'investigating'""",
                               (incident,)).fetchone()[0]
    has_review = conn.execute("SELECT 1 FROM analyst_review WHERE job_id = %s AND incident_id = %s",
                              (job, incident)).fetchone()
    if has_review is None:
        value = reopened_after_review(conn, job, incident)
        checks.check("reopened_after_review: 검토 행이 없으면 False", value is False, f"값 {value}")
    else:
        checks.skip("reopened_after_review: 검토 행이 없으면 False", "이 사건에는 실제 검토 행이 있다")
    for label, shift, want in [("결정이 재개보다 앞(결정 뒤에 다시 염)", "-1 minute", True),
                               ("결정이 재개보다 뒤(다시 연 뒤에 결정)", "1 minute", False)]:
        conn.execute("SAVEPOINT verify_review")
        # 실제 검토 행이 있으면 결정 시각만 바꿔 본다. SAVEPOINT로 되돌리므로 남지 않는다
        conn.execute("""INSERT INTO analyst_review (job_id, incident_id, requested_at, reason, action, analyst, decided_at)
                        VALUES (%s, %s, %s, 'verify_incident_reopen', 'dismiss', %s, %s::timestamptz + %s::interval)
                        ON CONFLICT (job_id, incident_id) DO UPDATE SET decided_at = EXCLUDED.decided_at""",
                     (job, incident, reopened_at, ACTOR, reopened_at, shift))
        value = reopened_after_review(conn, job, incident)
        conn.execute("ROLLBACK TO SAVEPOINT verify_review")
        conn.execute("RELEASE SAVEPOINT verify_review")
        checks.check(f"reopened_after_review: {label}이면 {want}", value is want, f"값 {value}")


def owner_part(conn, checks, job, incident, start, history_before):
    """zeekad_owner: 같은 흐름을 다시 하며 상태 행·이력·뷰·reopened_after_review의 뜻을 읽어 확인한다."""
    p = "[zeekad_owner] "
    expected = []                                    # 성공한 전이마다 이력 한 행: (이전, 다음, 결론, 왜)
    if start == "open":
        before = status_row(conn, incident)
        expect_error(conn, checks, p + "reopen_incident: 열림 사건", "22023", lambda: reopen(conn, job, incident))
        after = status_row(conn, incident)
        checks.check(p + "열림 사건 재개 거부 뒤 상태 행이 새로 생기지 않았다", after == before,
                     "상태 행 없음 그대로" if after is None else f"상태 행 {after[0]} 그대로")
    else:
        checks.skip(p + "거부: reopen_incident: 열림 사건", f"고른 사건이 이미 {start}이다")
        checks.skip(p + "열림 사건 재개 거부 뒤 상태 행이 새로 생기지 않았다", f"고른 사건이 이미 {start}이다")
    advance(conn, job, incident, start, expected)
    closed_row = status_row(conn, incident)
    prior = closed_row[1]                            # 재개로 되돌릴 결론

    wrong = other_resolution(prior)
    expect_error(conn, checks, p + f"reopen_incident: 기대 결론이 지금 결론과 다름({wrong} ≠ {prior})", "22023",
                 lambda: reopen(conn, job, incident, expected=wrong))
    expect_error(conn, checks, p + "reopen_incident: 기대 결론이 세 값이 아님", "22023",
                 lambda: reopen(conn, job, incident, expected="unknown"))
    row = status_row(conn, incident)
    checks.check(p + "기대 결론 거부 뒤 상태 행이 그대로(closed·같은 결론)", row == closed_row,
                 f"status={row[0]} resolution={row[1]}")

    got = reopen(conn, job, incident, expected=prior)
    expected.append(("closed", "investigating", None, REOPEN_REASON))
    checks.check(p + f"reopen_incident: 기대 결론이 같으면({prior}) closed → investigating", got == "investigating",
                 f"반환 {got}")
    row = status_row(conn, incident)
    checks.check("재개 뒤 상태 행: investigating, 결론 NULL, 누가·작업", row == ("investigating", None, ACTOR, job),
                 f"status={row[0]} resolution={row[1]} updated_by={row[2]} last_job_id={row[3]}")
    rows = conn.execute("""SELECT zeekad_status, zeekad_resolution FROM dashboard.incident_status
                           WHERE job_id = %s AND incident_id = %s""", (job, incident)).fetchall()
    checks.check("뷰 dashboard.incident_status: 재개 뒤 investigating·결론 NULL", rows == [("investigating", None)],
                 rows)
    rows = conn.execute("""SELECT zeekad_status, zeekad_resolution FROM dashboard.latest_incident_queue
                           WHERE incident_id = %s""", (incident,)).fetchall()
    checks.check("뷰 dashboard.latest_incident_queue: 재개 뒤 investigating·결론 NULL",
                 rows == [("investigating", None)], rows)
    review_semantics(conn, checks, job, incident)

    again = other_resolution(prior)
    transition(conn, job, incident, "closed", "검증: 다시 종료", again)
    expected.append(("investigating", "closed", again, "검증: 다시 종료"))
    row = status_row(conn, incident)
    checks.check("다시 종료 뒤 상태 행: 새 결론", row[:2] == ("closed", again), f"status={row[0]} resolution={row[1]}")

    rows = conn.execute("""SELECT history_id, job_id, from_status, to_status, resolution, actor, reason
                           FROM incident_status_history WHERE incident_id = %s AND history_id > %s
                           ORDER BY history_id""", (incident, history_before)).fetchall()
    want = [(job, frm, to, res, ACTOR, reason) for frm, to, res, reason in expected]
    checks.check("이력: 성공한 전이마다 한 행, 순서대로(거부한 호출은 행 없음)", [r[1:] for r in rows] == want,
                 f"{len(rows)}행, 기대 {len(want)}행: " + ", ".join(f"{r[2]}→{r[3]}" for r in rows))
    reopened = [r for r in rows if r[2:4] == ("closed", "investigating")]
    checks.check("이력: 재개 행(closed → investigating, 결론 NULL, 누가·왜)",
                 len(reopened) == 1 and reopened[0][4] is None and reopened[0][5:] == (ACTOR, REOPEN_REASON),
                 f"{len(reopened)}행")
    if reopened:
        last_close = conn.execute("""SELECT resolution FROM incident_status_history
                                     WHERE incident_id = %s AND to_status = 'closed' AND history_id < %s
                                     ORDER BY history_id DESC LIMIT 1""", (incident, reopened[0][0])).fetchone()
        checks.check("이력: 되돌린 결론은 앞선 종료 행에 남아 있다", last_close == (prior,),
                     f"앞선 종료 결론 {last_close and last_close[0]}, 재개 전 결론 {prior}")


def caller_role(dbname):
    """재개를 부를 계정. dashboard_rw로 접속할 수 있으면 그 계정, 아니면 소유자."""
    if not load_env().get("DASHBOARD_RW_PASSWORD"):
        print("재개 호출 계정: zeekad_owner(DASHBOARD_RW_PASSWORD가 없다)", flush=True)
        return "zeekad_owner"
    try:
        connect("dashboard_rw", dbname=dbname, autocommit=True).close()
    except psycopg.Error as e:
        print(f"재개 호출 계정: zeekad_owner(dashboard_rw로 접속하지 못했다: {type(e).__name__})", flush=True)
        return "zeekad_owner"
    print("재개 호출 계정: dashboard_rw(대시보드가 실제로 쓰는 계정)", flush=True)
    return "dashboard_rw"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default="zeekad", help="확인할 DB(기본 운영 DB zeekad)")
    args = parser.parse_args()
    checks = Checks()

    try:
        if not check_functions(args.db, checks):
            print(f"dashboard.reopen_incident가 없다. migration 018이 적용되지 않았다: "
                  f"python scripts/db_migrate.py --db {args.db}", flush=True)
            return 2
        with connect("zeekad_worker", dbname=args.db, autocommit=True) as conn:
            pick = conn.execute(PICK).fetchone()
            if pick is None:
                print("확인할 사건이 없다(성공한 채점 작업의 사건이 0건)", flush=True)
                return 1
            job, incident, capture, rank, start = pick
            before = snapshot(conn, job, incident)
    except psycopg.Error as e:
        print(f"DB 오류로 멈췄다: {summary(e)}", flush=True)
        return 1
    print(f"사건: {capture} 작업 {job} {rank}위, 시작 상태 {start}" + ("(상태 행 없음)" if before[0] is None else ""),
          flush=True)

    failed = False
    try:
        in_transaction(args.db, "zeekad_worker", lambda conn: worker_part(conn, checks, job, incident, start))
        role = caller_role(args.db)
        in_transaction(args.db, role, lambda conn: caller_part(conn, checks, job, incident, start, role))
        in_transaction(args.db, "zeekad_owner",
                       lambda conn: owner_part(conn, checks, job, incident, start, before[1][1]))
    except psycopg.Error as e:
        print(f"DB 오류로 멈췄다: {summary(e)}", flush=True)
        failed = True
    finally:
        try:
            with connect("zeekad_worker", dbname=args.db, autocommit=True) as conn:
                after = snapshot(conn, job, incident)
            checks.check("남긴 것 없음: 상태 행·이력·검토 행이 시작 전과 같다", after == before,
                         f"이력 {before[1][0]}행 → {after[1][0]}행")
        except psycopg.Error as e:
            print(f"남긴 것 확인 중 DB 오류: {summary(e)}", flush=True)
            failed = True
    print(f"{sum(checks.results)}/{len(checks.results)} 통과")
    return 1 if failed or not all(checks.results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
