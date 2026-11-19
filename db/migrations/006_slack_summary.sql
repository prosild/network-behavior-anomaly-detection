-- 006. Slack 일일 요약 기록(DD-001: 보내지 않은 사건의 개수와 ID를 공개한다).
-- 채점 작업(캡처 하루) 하나에 요약 하나. 같은 요약 버전은 한 번만 기록한다.
SET search_path = zeekad;

CREATE TABLE slack_summary (
    job_id          bigint NOT NULL REFERENCES scoring_job ON DELETE CASCADE,
    summary_version text NOT NULL,
    mode            text NOT NULL CHECK (mode IN ('dry_run', 'live')),
    payload         jsonb NOT NULL,
    payload_sha256  char(64) NOT NULL,
    status          text NOT NULL CHECK (status IN ('recorded', 'delivered', 'failed')),
    slack_ts        text,
    delivered_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, summary_version)
);

GRANT SELECT, INSERT, UPDATE ON slack_summary TO zeekad_worker;
GRANT SELECT ON slack_summary TO zeekad_api;
