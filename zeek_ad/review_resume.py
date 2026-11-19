"""분석가 검토 결정으로 멈춘 LangGraph 흐름을 재개한다(Q50 2번, DD-019).

대시보드는 dashboard.decide_review(DB 함수)로 결정만 넣는다(migration 014). 파이프라인이 "결정됐지만 아직 재개 안 된"
검토를 찾아(decided_reviews) 같은 thread(작업|사건)를 그 결정으로 재개한다(resume_one).
재개하면 analyst_review 노드가 결정을 다시 기록하고, apply_status가 사건 상태를 바꾸고 Slack 상태 알림을 남긴다.
실패는 오류 종류만 resume_error에 남기고 다시 고르지 않는다(같은 오류를 주기마다 반복하지 않게). 다시 하려면 명령줄 재개
(scripts/run_agent_graph.py resume)를 쓴다. 오류 문장에는 실제 IP가 섞일 수 있어 남기지 않는다.
"""

WAITING_NODE = "analyst_review"


def decided_reviews(conn):
    """결정됐지만 재개하지 않은 검토. 결정한 순서다."""
    rows = conn.execute("""SELECT job_id, incident_id, action, analyst, note FROM analyst_review
                           WHERE action IS NOT NULL AND resumed_at IS NULL AND resume_error IS NULL
                           ORDER BY decided_at, job_id, incident_id""").fetchall()
    return [{"job_id": r[0], "incident_id": r[1], "action": r[2], "analyst": r[3], "note": r[4]} for r in rows]


def thread_config(job_id, incident_id):
    return {"configurable": {"thread_id": f"{job_id}|{incident_id}"}}


def resume_one(graph, conn, review, command):
    """검토 하나를 재개한다. command: langgraph.types.Command(시험에서는 가짜). 반환: resumed·not_waiting·failed."""
    cfg = thread_config(review["job_id"], review["incident_id"])
    try:
        if WAITING_NODE not in (graph.get_state(cfg).next or ()):
            conn.execute("""UPDATE analyst_review SET resume_error = 'not_waiting'
                            WHERE job_id = %s AND incident_id = %s""", (review["job_id"], review["incident_id"]))
            return "not_waiting"
        payload = {k: review[k] for k in ("action", "analyst", "note")}
        for _ in graph.stream(command(resume=payload), cfg, stream_mode="updates"):
            pass
        if graph.get_state(cfg).next:                       # 끝나지 않고 다시 멈췄다(예상하지 못한 흐름)
            raise RuntimeError("재개 뒤에도 흐름이 끝나지 않았다")
    except Exception as e:  # noqa: BLE001 (한 검토의 실패가 다른 검토를 막지 않게)
        conn.execute("UPDATE analyst_review SET resume_error = %s WHERE job_id = %s AND incident_id = %s",
                     (type(e).__name__, review["job_id"], review["incident_id"]))
        return "failed"
    conn.execute("UPDATE analyst_review SET resumed_at = now() WHERE job_id = %s AND incident_id = %s",
                 (review["job_id"], review["incident_id"]))
    return "resumed"
