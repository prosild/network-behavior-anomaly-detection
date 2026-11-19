-- 007. LangGraph checkpoint 저장소와 분석가 검토 기록(단계 5b, DD-001·002).
--
-- langgraph 스키마: langgraph-checkpoint-postgres가 처음 실행 때 표(checkpoints 등)를 만든다(PostgresSaver.setup).
--   스키마는 zeekad_owner가 갖고, worker 계정에 USAGE·CREATE를 줘서 worker가 표를 만들게 한다. 그래프 상태(사건 사실 목록·보고서)가 들어가므로
--   API·대시보드 계정에는 권한을 주지 않는다.
-- analyst_review: 그래프가 interrupt로 멈춘 사건에 대한 분석가 결정. 재개할 때 그래프가 기록한다.
CREATE SCHEMA langgraph AUTHORIZATION zeekad_owner;
GRANT USAGE, CREATE ON SCHEMA langgraph TO zeekad_worker;

SET search_path = zeekad;

CREATE TABLE analyst_review (
    job_id       bigint NOT NULL,
    incident_id  text NOT NULL,
    requested_at timestamptz NOT NULL,             -- 그래프가 멈춘 시각
    reason       text NOT NULL,                    -- 멈춘 이유(예: decision_model=analyst_review)
    action       text CHECK (action IN ('confirm', 'dismiss')),   -- confirm: 조사 진행, dismiss: 오탐으로 종료
    analyst      text,
    note         text,
    decided_at   timestamptz,
    PRIMARY KEY (job_id, incident_id),
    FOREIGN KEY (job_id, incident_id) REFERENCES incident ON DELETE CASCADE
);

GRANT SELECT, INSERT, UPDATE ON analyst_review TO zeekad_worker;
GRANT SELECT ON analyst_review TO zeekad_api;
