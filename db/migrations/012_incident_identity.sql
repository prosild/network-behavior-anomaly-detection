-- 012. 사건 상태를 채점 작업이 아니라 사건 ID에 붙이고, 캡처별 최신 큐 뷰를 더한다(데이터 계약 v2.1, Q54).
--
-- 배경: 실습망(DD-012)은 파일이 올 때마다 그날을 다시 계산해 같은 캡처에 채점 작업이 여러 개 생긴다.
-- 같은 사건(incident_id = 캡처|자산|역할|시작 epoch)이 작업마다 따로 나오는데, 상태가 (job_id, incident_id)에 붙어 있어
-- 새 작업에서는 open으로 되돌아간 것처럼 보였다. 보고서·판단도 처음 처리한 작업에만 있다.
-- 바꾸는 것
-- 1. incident_status의 키를 incident_id 하나로 바꾼다. job_id 열은 last_job_id(마지막으로 바꿀 때 보던 작업)로 이름을 바꾼다.
--    채점 작업을 지워도 분석가의 판단은 남도록 작업 외래 키를 뺀다.
-- 2. incident_status_history도 작업 외래 키를 뺀다. 추가만 되는 감사 기록이라 작업을 지워도 남아야 한다.
-- 3. transition_incident 함수: 호출 모양은 그대로다. 사건 ID로 상태 행을 잠그고 바꾼다.
-- 4. 뷰 dashboard.incident_status: 열은 그대로, 같은 사건 ID면 어느 작업에서 보든 같은 상태가 나온다.
-- 5. 새 뷰 dashboard.latest_incident_queue: 캡처마다 가장 최근 성공 작업의 큐에, 사건 ID로 찾은 보고서 작업·전송 여부·상태·검토를 붙인다.
SET search_path = zeekad;

ALTER TABLE incident_status DROP CONSTRAINT incident_status_job_id_incident_id_fkey;
ALTER TABLE incident_status DROP CONSTRAINT incident_status_pkey;
ALTER TABLE incident_status RENAME COLUMN job_id TO last_job_id;
ALTER TABLE incident_status ADD PRIMARY KEY (incident_id);
ALTER TABLE incident_status_history DROP CONSTRAINT incident_status_history_job_id_incident_id_fkey;
CREATE INDEX incident_status_history_incident ON incident_status_history (incident_id, changed_at);

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
    -- 화면이 보고 있던 작업에 그 사건이 있는지 확인한다(엉뚱한 사건 ID를 막는다). 상태는 사건 ID 하나에 붙는다.
    IF NOT EXISTS (SELECT 1 FROM incident WHERE job_id = p_job AND incident_id = p_incident) THEN
        RAISE EXCEPTION '사건이 없다: % %', p_job, p_incident USING ERRCODE = '02000';
    END IF;
    INSERT INTO incident_status (incident_id, last_job_id, status, updated_by)
    VALUES (p_incident, p_job, 'open', 'system') ON CONFLICT DO NOTHING;
    SELECT status INTO v_from FROM incident_status WHERE incident_id = p_incident FOR UPDATE;

    IF NOT ((v_from = 'open' AND p_to = 'investigating') OR (v_from = 'investigating' AND p_to = 'closed')) THEN
        RAISE EXCEPTION '허용되지 않는 상태 변경: % → %', v_from, p_to USING ERRCODE = '22023';
    END IF;
    IF p_to = 'closed' AND (p_resolution IS NULL OR p_resolution NOT IN ('true_positive', 'false_positive', 'benign')) THEN
        RAISE EXCEPTION '종료할 때는 결론(true_positive·false_positive·benign)이 필요하다' USING ERRCODE = '22023';
    END IF;
    IF p_to <> 'closed' AND p_resolution IS NOT NULL THEN
        RAISE EXCEPTION '결론은 종료할 때만 적는다' USING ERRCODE = '22023';
    END IF;

    UPDATE incident_status SET status = p_to, resolution = p_resolution, updated_at = now(), updated_by = p_actor,
                               last_job_id = p_job
    WHERE incident_id = p_incident;
    INSERT INTO incident_status_history (job_id, incident_id, from_status, to_status, resolution, actor, reason)
    VALUES (p_job, p_incident, v_from, p_to, p_resolution, p_actor, p_reason);
    RETURN p_to;
END
$$;

CREATE OR REPLACE VIEW dashboard.incident_status AS
SELECT i.job_id, i.incident_id, coalesce(s.status, 'open') AS zeekad_status, s.resolution AS zeekad_resolution,
       s.updated_at, s.updated_by
FROM incident i
JOIN scoring_job j ON j.job_id = i.job_id AND j.status = 'succeeded'
LEFT JOIN incident_status s ON s.incident_id = i.incident_id;

-- 캡처별 최신 큐. 화면의 "오늘 조사 큐"는 이 뷰 하나로 그린다.
-- zeekad_report_job_id: 이 사건의 보고서·전송 판단·Slack 기록·검토가 있는 작업. 그 뷰들과 조인할 때는 job_id 대신 이 값을 쓴다.
CREATE VIEW dashboard.latest_incident_queue AS
WITH latest AS (
    SELECT DISTINCT ON (capture_id) capture_id, job_id
    FROM scoring_job WHERE status = 'succeeded'
    ORDER BY capture_id, job_id DESC
)
SELECT q.job_id, q.capture_id, q.bundle_id, q.queue_rank, q.incident_id, q.host_ip, q.zeekad_role,
       q.event_start, q.event_end, q.zeekad_picked_by, q.zeekad_also_flagged_by, q.connection_count, q.host_name,
       rep.job_id AS zeekad_report_job_id, rep.report_kind AS zeekad_report_kind,
       d.would_send AS zeekad_would_send,
       coalesce(s.status, 'open') AS zeekad_status, s.resolution AS zeekad_resolution, s.updated_at AS status_updated_at,
       rv.action AS zeekad_review_action, (rv.requested_at IS NOT NULL AND rv.action IS NULL) AS zeekad_review_pending
FROM dashboard.incident_queue q
JOIN latest l ON l.job_id = q.job_id
LEFT JOIN LATERAL (
    SELECT r.job_id, r.report_kind FROM agent_report r
    WHERE r.incident_id = q.incident_id ORDER BY r.job_id DESC LIMIT 1) rep ON true
LEFT JOIN send_decision d ON d.job_id = rep.job_id AND d.incident_id = q.incident_id
LEFT JOIN incident_status s ON s.incident_id = q.incident_id
LEFT JOIN LATERAL (
    SELECT a.action, a.requested_at FROM analyst_review a
    WHERE a.incident_id = q.incident_id ORDER BY a.requested_at DESC LIMIT 1) rv ON true;

GRANT SELECT ON dashboard.latest_incident_queue TO dashboard_ro, zeekad_api;
