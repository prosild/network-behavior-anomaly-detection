-- 010. 데이터 계약 v2: 단계 5b 결과(보고서·전송 판단·Slack 기록)를 대시보드 뷰로 연다.
--
-- 원칙(계약 v1과 같다)
-- - 대시보드 계정(dashboard_ro)은 dashboard 스키마 뷰만 읽는다. 원래 표 구조가 바뀌어도 뷰의 열 이름과 뜻은 유지한다.
-- - jsonb 안의 자주 쓰는 값은 열로 꺼낸다(Java가 JSON 경로를 몰라도 되게). 화면에 통째로 그릴 본문만 jsonb로 둔다.
-- - 완료(succeeded)된 채점 작업의 사건만 보인다(incident_queue와 같은 조건).
-- 열지 않는 것
-- - LLM 원래 출력(agent_report.llm_call.report): 검증에 실패한 글일 수 있다. 화면에는 최종 보고서(report)만 보인다.
-- - langgraph 스키마(그래프 상태): 사실 목록·입력 전체가 들어 있어 worker만 읽는다(007).
SET search_path = zeekad;

-- 사건 보고서: 사건마다 하나. report_kind가 template이면 LLM 보고서가 검증에 실패했거나 호출이 실패한 것이다.
CREATE VIEW dashboard.incident_reports AS
SELECT r.job_id, r.incident_id,
       r.report_kind AS zeekad_report_kind, r.report_version AS zeekad_report_version,
       r.input_version AS zeekad_input_version,
       r.report AS zeekad_report,
       (r.verification->>'passed')::boolean AS zeekad_verification_passed,
       r.verification->>'reason' AS zeekad_verification_reason,
       r.verification->'problems' AS zeekad_verification_problems,
       r.llm_call->>'model' AS llm_model_requested,
       r.llm_call->>'model_version' AS llm_model_version,
       (r.llm_call->>'seconds')::double precision AS llm_seconds,
       (r.llm_call->'usage'->>'input')::integer AS llm_input_tokens,
       (r.llm_call->'usage'->>'output')::integer AS llm_output_tokens,
       (r.llm_call->'usage'->>'thinking')::integer AS llm_thinking_tokens,
       r.llm_call->>'error' AS llm_error,
       r.attack_candidates AS zeekad_attack_candidates,
       r.source_run AS zeekad_source_run, r.created_at
FROM agent_report r
JOIN scoring_job j ON j.job_id = r.job_id AND j.status = 'succeeded';

-- 전송 판단: 같은 사건에 대한 세 의견. A단계(DD-001)라 실제 전송 여부(would_send)는 정책 규칙이 정한다.
CREATE VIEW dashboard.send_decisions AS
SELECT d.job_id, d.incident_id,
       d.would_send AS zeekad_would_send, d.decided_by AS zeekad_decided_by,
       d.policy->>'policy_id' AS policy_id, d.policy->>'choice' AS policy_choice,
       (d.policy->>'mandatory')::boolean AS policy_mandatory, d.policy->'reasons' AS policy_reasons,
       d.llm_choice,
       d.decision_model->>'model' AS decision_model,
       d.decision_model->>'choice' AS decision_model_choice,
       (d.decision_model->>'confidence')::double precision AS decision_model_confidence,
       d.decision_model->'probabilities' AS decision_model_probabilities,
       d.decision_model->>'error' AS decision_model_error,
       d.source_run AS zeekad_source_run, d.created_at
FROM send_decision d
JOIN scoring_job j ON j.job_id = d.job_id AND j.status = 'succeeded';

-- Slack 전송 기록: 사건 알림(report_version = 보고서 버전)과 상태 후속 알림(report_version = 'status:<상태>').
CREATE VIEW dashboard.slack_deliveries AS
SELECT s.job_id, s.incident_id,
       CASE WHEN s.report_version LIKE 'status:%' THEN 'status' ELSE 'incident' END AS zeekad_message_kind,
       s.report_version AS zeekad_message_version,
       s.mode AS zeekad_delivery_mode, s.status AS zeekad_delivery_status,
       s.payload AS slack_payload, s.slack_ts, s.delivered_at, s.error, s.created_at
FROM slack_delivery s
JOIN scoring_job j ON j.job_id = s.job_id AND j.status = 'succeeded';

-- Slack 일일 요약: 채점 작업(캡처 하루)마다 하나. 보내지 않은 사건 수와 ID를 공개한다(DD-001).
CREATE VIEW dashboard.slack_summaries AS
SELECT s.job_id, j.capture_id, s.summary_version AS zeekad_message_version,
       s.mode AS zeekad_delivery_mode, s.status AS zeekad_delivery_status,
       s.payload AS slack_payload, s.slack_ts, s.delivered_at, s.created_at
FROM slack_summary s
JOIN scoring_job j ON j.job_id = s.job_id AND j.status = 'succeeded';

GRANT SELECT ON dashboard.incident_reports, dashboard.send_decisions, dashboard.slack_deliveries,
    dashboard.slack_summaries TO dashboard_ro, zeekad_api;
