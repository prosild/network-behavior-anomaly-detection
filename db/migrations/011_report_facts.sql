-- 011. 보고서가 인용한 사실 목록과 가명표를 저장한다(데이터 계약 v2 보완, 2026-11-17 사용자 결정).
--
-- 보고서 문장은 사실 번호(F23)와 가명(H, I1, X1)으로 쓴다. 대시보드가 이를 실제 값으로 풀려면 두 가지가 필요하다.
-- - facts: LLM에 보낸 사실 목록 그대로(가명·상대 초, 실제 IP 없음). 보고서를 쓸 때의 목록이다(추가 근거로 늘어나기 전).
-- - pseudonyms: {가명: 실제 IP}. DB에만 둔다. LLM·판단 모델에는 보내지 않는다(설계 9.1절).
-- 기존 행은 scripts/backfill_report_facts.py로 채운다. 그 전에는 null이다.
SET search_path = zeekad;

ALTER TABLE agent_report ADD COLUMN facts jsonb, ADD COLUMN pseudonyms jsonb;

-- 뷰 끝에 열 두 개를 붙인다(CREATE OR REPLACE VIEW는 끝에 추가하는 것만 허용한다. 기존 열은 그대로다).
CREATE OR REPLACE VIEW dashboard.incident_reports AS
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
       r.source_run AS zeekad_source_run, r.created_at,
       r.facts AS zeekad_facts, r.pseudonyms AS zeekad_pseudonyms
FROM agent_report r
JOIN scoring_job j ON j.job_id = r.job_id AND j.status = 'succeeded';
