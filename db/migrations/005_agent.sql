-- 005. 단계 5b 결과 표: 사건 보고서, 전송 판단(그림자 비교), Slack 전송 기록(DD-001·011·014).
--
-- agent_report: 사건마다 화면·알림에 쓰는 보고서 하나(LLM 검증 통과면 LLM, 아니면 템플릿)와 LLM 원래 출력·검증 결과.
-- send_decision: 같은 사건에 대한 세 판단(정책 규칙·일반 LLM·판단 모델). A단계라 would_send는 정책 규칙이 정한다.
-- slack_delivery: 전송 기록. (job_id, incident_id, report_version)이 유일해서 재시도해도 한 번만 남는다.
--   mode가 dry_run이면 Slack에 보내지 않고 보낼 내용(payload)만 남긴다. delivered_at은 실제 전송 성공 시각이다.
SET search_path = zeekad;

CREATE TABLE agent_report (
    job_id          bigint NOT NULL,
    incident_id     text NOT NULL,
    input_version   text NOT NULL,                 -- 예: llm-input.v2
    report_kind     text NOT NULL CHECK (report_kind IN ('llm', 'template')),
    report_version  text NOT NULL,                 -- 예: llm-report.v1, template.v1
    report          jsonb NOT NULL,                -- 화면·알림에 쓰는 보고서
    verification    jsonb NOT NULL,                -- {passed, reason, problems}
    llm_call        jsonb NOT NULL,                -- 요청 모델·응답 model_version·지연·토큰·오류·LLM 원래 출력
    attack_candidates jsonb NOT NULL,              -- 검색한 ATT&CK 후보(가설)
    source_run      text NOT NULL,                 -- 만든 실행 폴더(재현용)
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, incident_id),
    FOREIGN KEY (job_id, incident_id) REFERENCES incident ON DELETE CASCADE
);

CREATE TABLE send_decision (
    job_id          bigint NOT NULL,
    incident_id     text NOT NULL,
    policy          jsonb NOT NULL,                -- {policy_id, choice, mandatory, reasons}
    llm_choice      text,
    decision_model  jsonb NOT NULL,                -- {model, choice, probabilities, confidence, seconds, error}
    would_send      boolean NOT NULL,
    decided_by      text NOT NULL,                 -- A단계: policy
    source_run      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, incident_id),
    FOREIGN KEY (job_id, incident_id) REFERENCES incident ON DELETE CASCADE
);

CREATE TABLE slack_delivery (
    job_id          bigint NOT NULL,
    incident_id     text NOT NULL,
    report_version  text NOT NULL,
    mode            text NOT NULL CHECK (mode IN ('dry_run', 'live')),
    payload         jsonb NOT NULL,                -- Slack에 보낼(보냈을) 메시지 본문
    payload_sha256  char(64) NOT NULL,
    status          text NOT NULL CHECK (status IN ('recorded', 'delivered', 'failed')),
    slack_ts        text,                          -- 실제 전송 시 Slack 메시지 식별자
    delivered_at    timestamptz,
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, incident_id, report_version),
    FOREIGN KEY (job_id, incident_id) REFERENCES incident ON DELETE CASCADE
);

GRANT SELECT, INSERT, UPDATE ON agent_report, send_decision, slack_delivery TO zeekad_worker;
GRANT SELECT ON agent_report, send_decision, slack_delivery TO zeekad_api;
