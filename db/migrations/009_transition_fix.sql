-- 009. transition_incident 수정: 종료할 때 결론이 비어 있으면(NULL) 함수가 안내 문장으로 거부한다.
-- 008에서는 NULL NOT IN (...)이 참이 아니라 NULL이라 함수 검사를 지나쳤고, 표의 CHECK 제약이 대신 막았다.
-- CREATE OR REPLACE는 실행 권한(GRANT)을 그대로 둔다.
CREATE OR REPLACE FUNCTION dashboard.transition_incident(p_job bigint, p_incident text, p_to text, p_actor text,
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
    IF p_to = 'closed' AND (p_resolution IS NULL OR p_resolution NOT IN ('true_positive', 'false_positive', 'benign')) THEN
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

