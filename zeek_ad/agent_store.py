"""5b 결과를 DB 표(agent_report·send_decision)에 쓴다. 배치 적재 스크립트와 LangGraph가 같이 쓴다.

같은 사건이 이미 있으면 새 결과로 바꾼다(가장 최근 실행이 그 사건의 결과다).
실습망에서 어떤 사건을 (다시) 처리할지도 여기서 고른다(incidents_to_report, DD-016 결정 3).
"""

from psycopg.types.json import Jsonb


def save_report(conn, job_id, incident_id, llm_input, report, report_kind, verification, llm_call, source_run,
                pseudonyms):
    """보고서 저장. facts는 llm_input의 사실 목록(보고서를 쓸 때의 것), pseudonyms는 agent_inputs.pseudonym_map 결과."""
    conn.execute("""INSERT INTO agent_report (job_id, incident_id, input_version, report_kind, report_version,
                        report, verification, llm_call, attack_candidates, source_run, facts, pseudonyms)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (job_id, incident_id) DO UPDATE SET
                        input_version = EXCLUDED.input_version, report_kind = EXCLUDED.report_kind,
                        report_version = EXCLUDED.report_version, report = EXCLUDED.report,
                        verification = EXCLUDED.verification, llm_call = EXCLUDED.llm_call,
                        attack_candidates = EXCLUDED.attack_candidates, source_run = EXCLUDED.source_run,
                        facts = EXCLUDED.facts, pseudonyms = EXCLUDED.pseudonyms, created_at = now()""",
                 (job_id, incident_id, llm_input["version"], report_kind, report["report_version"], Jsonb(report),
                  Jsonb(verification), Jsonb(llm_call), Jsonb(llm_input["attack_candidates"]), source_run,
                  Jsonb(llm_input["facts"]), Jsonb(pseudonyms)))


def report_reason(job_id, windows, report_job, reported_windows, decided=True):
    """사건 하나를 이 작업에서 처리할 이유. 'new'(보고서 없음), 'changed'(창이 달라짐), 'retry'(끝까지 못 감), None(건너뜀).

    windows: 이 작업에서 사건을 이루는 창 시작 목록(정렬). report_job·reported_windows: 가장 최근 보고서를 만든 작업과
    그 작업에서의 창 목록. 보고서가 본 창 목록은 따로 저장하지 않는다. 보고서는 (작업, 사건) 키라 그 작업의
    incident_window가 곧 보고서가 본 창이다.
    decided: 그 보고서 작업에 전송 판단(send_decision)이 있는가. 판단은 흐름의 마지막 쓰기라, 없으면 보고서를 쓴 뒤
    판단·전송 단계에서 실패한 것이다. 그때는 다시 처리한다.
    """
    if report_job is None:
        return "new"
    if report_job != job_id and list(windows) != list(reported_windows or []):
        return "changed"
    return None if decided else "retry"     # 같은 창(또는 이 작업에서 이미 처리): 판단까지 끝났으면 건너뛴다


def incidents_to_report(conn, job_id, capture_id):
    """이 작업에서 보고서를 (다시) 만들 사건. 반환: [(incident_id, 'new'·'changed'·'retry')], 큐 순위 순서.

    실습망은 같은 날을 여러 번 다시 계산한다(DD-012). 같은 사건 ID(캡처|자산|역할|시작)가 작업마다 나오는데,
    뒤 파일에서 창이 이어 붙으면 사건이 늘어난다(예: ping 뒤의 nmap). 그때는 보고서를 다시 만든다(DD-016 결정 3).
    시작 창이 바뀌면 사건 ID가 달라져 'new'가 된다.
    """
    rows = conn.execute("""
        WITH cur AS (
            SELECT i.incident_id, i.queue_rank, array_agg(w.window_start ORDER BY w.window_start) AS windows
            FROM incident i JOIN incident_window w USING (job_id, incident_id)
            WHERE i.job_id = %(job)s GROUP BY i.incident_id, i.queue_rank),
        rep AS (
            SELECT DISTINCT ON (r.incident_id) r.incident_id, r.job_id
            FROM agent_report r JOIN scoring_job j ON j.job_id = r.job_id
            WHERE j.capture_id = %(cap)s ORDER BY r.incident_id, r.job_id DESC)
        SELECT c.incident_id, c.windows, rep.job_id,
               (SELECT array_agg(w.window_start ORDER BY w.window_start) FROM incident_window w
                WHERE w.job_id = rep.job_id AND w.incident_id = c.incident_id),
               EXISTS (SELECT 1 FROM send_decision d WHERE d.job_id = rep.job_id AND d.incident_id = c.incident_id)
        FROM cur c LEFT JOIN rep USING (incident_id)
        ORDER BY c.queue_rank""", {"job": job_id, "cap": capture_id}).fetchall()
    out = []
    for iid, windows, report_job, reported, decided in rows:
        reason = report_reason(job_id, windows, report_job, reported, decided)
        if reason:
            out.append((iid, reason))
    return out


def save_decision(conn, job_id, incident_id, policy, llm_choice, decision_model, shadow, source_run):
    conn.execute("""INSERT INTO send_decision (job_id, incident_id, policy, llm_choice, decision_model,
                        would_send, decided_by, source_run)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (job_id, incident_id) DO UPDATE SET
                        policy = EXCLUDED.policy, llm_choice = EXCLUDED.llm_choice,
                        decision_model = EXCLUDED.decision_model, would_send = EXCLUDED.would_send,
                        decided_by = EXCLUDED.decided_by, source_run = EXCLUDED.source_run, created_at = now()""",
                 (job_id, incident_id, Jsonb(policy), llm_choice, Jsonb(decision_model), shadow["would_send"],
                  shadow["decided_by"], source_run))
