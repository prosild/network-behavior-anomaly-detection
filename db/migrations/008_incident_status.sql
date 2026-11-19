-- 008. 사건 상태 흐름(DD-010): 열림(open) → 확인 중(investigating) → 종료(closed).
--
-- 규칙(DB 함수가 강제한다. 화면이나 호출하는 쪽을 믿지 않는다):
-- - 한 칸씩만 앞으로 간다. 역방향(종료 → 열림 등)과 건너뛰기(열림 → 종료)는 막는다.
-- - 종료할 때는 결론(resolution)을 고른다: true_positive(실제 공격), false_positive(오탐), benign(이상하지만 정상 업무).
-- - 바꿀 때마다 누가(actor), 언제, 왜(reason)를 이력에 남긴다. 이력 표는 추가만 되고 고치거나 지울 수 없다(권한으로 막음).
-- - 상태 행이 없는 사건은 열림이다(사건이 수백 건이라 미리 만들지 않는다).
-- 쓰는 방법은 dashboard.transition_incident 함수 하나뿐이다. dashboard_rw(대시보드)와 zeekad_worker(LangGraph)가 실행한다.
-- 함수는 소유자(zeekad_owner) 권한으로 돈다(SECURITY DEFINER). 그래서 호출하는 계정에는 표 쓰기 권한을 주지 않는다.
SET search_path = zeekad;

CREATE TABLE incident_status (
    job_id      bigint NOT NULL,
    incident_id text NOT NULL,
    status      text NOT NULL CHECK (status IN ('open', 'investigating', 'closed')),
    resolution  text CHECK (resolution IN ('true_positive', 'false_positive', 'benign')),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text NOT NULL,
    PRIMARY KEY (job_id, incident_id),
    FOREIGN KEY (job_id, incident_id) REFERENCES incident ON DELETE CASCADE,
    CHECK ((status = 'closed') = (resolution IS NOT NULL))
);

CREATE TABLE incident_status_history (
    history_id  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id      bigint NOT NULL,
    incident_id text NOT NULL,
    from_status text NOT NULL,
    to_status   text NOT NULL,
    resolution  text,
    actor       text NOT NULL,
    reason      text NOT NULL,
    changed_at  timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (job_id, incident_id) REFERENCES incident ON DELETE CASCADE
);

CREATE FUNCTION dashboard.transition_incident(p_job bigint, p_incident text, p_to text, p_actor text,
                                              p_reason text, p_resolution text DEFAULT NULL)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = zeekad, pg_temp            -- 호출하는 쪽의 search_path로 다른 표를 끼워 넣지 못하게 고정한다
AS $$
DECLARE
    v_from text;
BEGIN
    IF coalesce(btrim(p_actor), '') = '' OR coalesce(btrim(p_reason), '') = '' THEN
        RAISE EXCEPTION '누가(actor)와 왜(reason)를 적어야 한다' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM incident WHERE job_id = p_job AND incident_id = p_incident) THEN
        RAISE EXCEPTION '사건이 없다: % %', p_job, p_incident USING ERRCODE = '02000';
    END IF;
    -- 처음 바꾸는 사건이면 열림 행을 만들고, 같은 사건을 동시에 바꾸지 못하게 행을 잠근다
    INSERT INTO incident_status (job_id, incident_id, status, updated_by)
    VALUES (p_job, p_incident, 'open', 'system') ON CONFLICT DO NOTHING;
    SELECT status INTO v_from FROM incident_status
    WHERE job_id = p_job AND incident_id = p_incident FOR UPDATE;

    IF NOT ((v_from = 'open' AND p_to = 'investigating') OR (v_from = 'investigating' AND p_to = 'closed')) THEN
        RAISE EXCEPTION '허용되지 않는 상태 변경: % → %', v_from, p_to USING ERRCODE = '22023';
    END IF;
    IF p_to = 'closed' AND p_resolution NOT IN ('true_positive', 'false_positive', 'benign') THEN
        RAISE EXCEPTION '종료할 때는 결론(true_positive·false_positive·benign)이 필요하다' USING ERRCODE = '22023';
    END IF;
    IF p_to <> 'closed' AND p_resolution IS NOT NULL THEN
        RAISE EXCEPTION '결론은 종료할 때만 적는다' USING ERRCODE = '22023';
    END IF;

    UPDATE incident_status SET status = p_to, resolution = p_resolution, updated_at = now(), updated_by = p_actor
    WHERE job_id = p_job AND incident_id = p_incident;
    INSERT INTO incident_status_history (job_id, incident_id, from_status, to_status, resolution, actor, reason)
    VALUES (p_job, p_incident, v_from, p_to, p_resolution, p_actor, p_reason);
    RETURN p_to;
END
$$;

-- 함수는 기본으로 누구나 실행할 수 있다(PUBLIC). 두 계정만 남긴다.
REVOKE ALL ON FUNCTION dashboard.transition_incident(bigint, text, text, text, text, text) FROM PUBLIC;
GRANT USAGE ON SCHEMA dashboard TO dashboard_rw, zeekad_worker;
GRANT EXECUTE ON FUNCTION dashboard.transition_incident(bigint, text, text, text, text, text)
    TO dashboard_rw, zeekad_worker;
-- 읽기: worker·API는 표를, 대시보드는 아래 뷰를 읽는다. 쓰기 권한은 아무 계정에도 주지 않는다(함수로만 쓴다).
GRANT SELECT ON incident_status, incident_status_history TO zeekad_worker, zeekad_api;

-- 대시보드 뷰(데이터 계약 v2에서 추가, 기존 뷰는 바꾸지 않는다)
CREATE VIEW dashboard.incident_status AS
SELECT i.job_id, i.incident_id, coalesce(s.status, 'open') AS zeekad_status, s.resolution AS zeekad_resolution,
       s.updated_at, s.updated_by
FROM incident i
JOIN scoring_job j ON j.job_id = i.job_id AND j.status = 'succeeded'
LEFT JOIN incident_status s ON s.job_id = i.job_id AND s.incident_id = i.incident_id;

CREATE VIEW dashboard.incident_status_history AS
SELECT job_id, incident_id, from_status, to_status, resolution AS zeekad_resolution, actor, reason, changed_at
FROM incident_status_history;

CREATE VIEW dashboard.analyst_review_queue AS
SELECT r.job_id, r.incident_id, i.queue_rank, host(i.asset_id) AS host_ip, i.role AS zeekad_role,
       r.reason AS zeekad_review_reason, r.requested_at, r.action AS zeekad_review_action, r.analyst, r.decided_at
FROM analyst_review r JOIN incident i USING (job_id, incident_id);

GRANT SELECT ON dashboard.incident_status, dashboard.incident_status_history, dashboard.analyst_review_queue
    TO dashboard_ro, zeekad_api;
