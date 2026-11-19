-- 014. 분석가 검토 결정 경로(Q50 2번, DD-019).
--
-- 대시보드는 사건 상태를 바꿀 때처럼 DB 함수(dashboard.decide_review) 하나로 검토 결정을 넣는다.
-- 함수는 결정을 기록할 뿐이다. 멈춘 LangGraph 흐름은 파이프라인(감시 프로그램 → scripts/resume_reviews.py)이
-- "결정됐지만 아직 재개 안 된" 검토를 찾아 재개한다. 근거 API는 읽기 전용 그대로 두고, Gemini 키·LangGraph 상태는
-- 파이프라인 쪽에만 둔다.
-- 규칙(함수가 강제한다. 화면이나 호출하는 쪽을 믿지 않는다):
-- - 결정 값은 confirm(조사 진행) 또는 dismiss(오탐으로 종료). 누가(analyst) 결정했는지 반드시 적는다.
-- - 검토 요청 행이 있어야 하고, 한 번만 결정한다(이미 결정한 요청은 바꾸지 않는다).
SET search_path = zeekad;

ALTER TABLE analyst_review
    ADD COLUMN resumed_at   timestamptz,           -- 파이프라인이 멈춘 흐름을 재개해 끝낸 시각
    ADD COLUMN resume_error text;                  -- 재개 실패 이유(오류 종류만. 다시 하려면 명령줄 재개)

CREATE FUNCTION dashboard.decide_review(p_job bigint, p_incident text, p_action text, p_analyst text,
                                        p_note text DEFAULT NULL)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = zeekad, pg_temp            -- 호출하는 쪽의 search_path로 다른 표를 끼워 넣지 못하게 고정한다
AS $$
DECLARE
    v_action text;
BEGIN
    IF p_action IS NULL OR p_action NOT IN ('confirm', 'dismiss') THEN
        RAISE EXCEPTION '결정은 confirm 또는 dismiss다' USING ERRCODE = '22023';
    END IF;
    IF coalesce(btrim(p_analyst), '') = '' THEN
        RAISE EXCEPTION '누가(analyst) 결정했는지 적어야 한다' USING ERRCODE = '22023';
    END IF;
    -- 같은 요청을 동시에 결정하지 못하게 행을 잠근다
    SELECT action INTO v_action FROM analyst_review
    WHERE job_id = p_job AND incident_id = p_incident FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION '검토 요청이 없다: % %', p_job, p_incident USING ERRCODE = '02000';
    END IF;
    IF v_action IS NOT NULL THEN
        RAISE EXCEPTION '이미 결정한 검토 요청이다(%)', v_action USING ERRCODE = '22023';
    END IF;
    UPDATE analyst_review SET action = p_action, analyst = p_analyst, note = p_note, decided_at = now()
    WHERE job_id = p_job AND incident_id = p_incident;
    RETURN p_action;
END
$$;

-- 함수는 기본으로 누구나 실행할 수 있다(PUBLIC). 대시보드(dashboard_rw)와 worker(명령줄·시험)만 남긴다.
REVOKE ALL ON FUNCTION dashboard.decide_review(bigint, text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dashboard.decide_review(bigint, text, text, text, text) TO dashboard_rw, zeekad_worker;

-- 검토 목록 뷰: 기존 열은 그대로 두고 재개 결과 두 열을 뒤에 더한다
CREATE OR REPLACE VIEW dashboard.analyst_review_queue AS
SELECT r.job_id, r.incident_id, i.queue_rank, host(i.asset_id) AS host_ip, i.role AS zeekad_role,
       r.reason AS zeekad_review_reason, r.requested_at, r.action AS zeekad_review_action, r.analyst, r.decided_at,
       r.resumed_at AS zeekad_review_resumed_at, (r.resume_error IS NOT NULL) AS zeekad_review_resume_failed
FROM analyst_review r JOIN incident i USING (job_id, incident_id);
