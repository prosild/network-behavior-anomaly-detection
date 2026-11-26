-- 019. 최신 큐 뷰가 사건마다 "가장 최근 보고서"를 찾을 때 쓰는 인덱스(Q87).
--
-- 배경: dashboard.latest_incident_queue(012)는 사건 행마다
--   SELECT r.job_id, r.report_kind FROM agent_report r WHERE r.incident_id = q.incident_id ORDER BY r.job_id DESC LIMIT 1
-- 을 한다. agent_report에는 기본 키 (job_id, incident_id) 인덱스만 있어 행마다 그 인덱스 전체를 거꾸로 훑는다.
-- 보고서가 333행에서 2,857행으로 늘자(대부분 lab-20261123의 템플릿) 대시보드 목록·상세가 3~3.7배 느려졌다.
-- 대시보드가 일회용 DB에서 이 인덱스로 같은 문장이 133~180ms → 16~61ms가 되고 결과가 같은 것을 확인했다.
-- 바꾸는 것: 인덱스 하나. 표·뷰·함수·권한과 조회 결과는 바뀌지 않는다. 다시 실행해도 같다(IF NOT EXISTS).
-- 이름 agent_report_incident_job_idx는 대시보드의 공개용 DB 사본과 맞춘 이름이다(같은 이름이면 사본 쪽 생성은 건너뛴다).
SET search_path = zeekad;

CREATE INDEX IF NOT EXISTS agent_report_incident_job_idx ON agent_report (incident_id, job_id DESC);
