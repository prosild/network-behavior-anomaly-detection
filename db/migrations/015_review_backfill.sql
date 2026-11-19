-- 015. 014 이전에 결정된 분석가 검토를 "재개됨"으로 표시한다(DD-019).
--
-- 014 전에는 결정을 그래프 재개(scripts/run_agent_graph.py resume)나 일반 함수 버전(agent_pipeline.resume_review)으로만
-- 넣을 수 있었다. 그래서 그때 결정된 검토는 처리가 이미 끝났다. 014 직후 감시 프로그램이 이 행들을 "결정됐지만 재개 안 됨"으로
-- 보고 재개를 시도해 resume_error = 'not_waiting'으로 남겼다(배포 VM, 2026-11-19, CIC 작업 4의 시험 검토 2건).
-- 기준 시각은 014를 적용한 시각이다. 그 뒤에 결정된 검토(대시보드 결정)는 건드리지 않는다.
SET search_path = zeekad;

UPDATE analyst_review r
SET resumed_at = r.decided_at, resume_error = NULL
FROM schema_migrations m
WHERE m.name = '014_review_decision.sql'
  AND r.action IS NOT NULL
  AND r.decided_at < m.applied_at
  AND r.resumed_at IS NULL;
