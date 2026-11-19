-- 002. 근거·자산 관측 표와 대시보드 읽기 전용 뷰(단계 4 5번, DD-010).
--
-- asset_observation: Zeek 로그에 실제로 나온 자산 이름(kerberos·ntlm). 관측하지 않은 값은 없다.
-- incident_evidence: 사건 창의 연결 요약(ECS 이름의 JSON). 원본 연결은 Parquet 이벤트 표에 있고 여기는 요약과 대표 uid다.
-- dashboard 스키마: Java 대시보드가 읽는 뷰만 둔다. dashboard_ro는 이 뷰만 읽고 원래 표는 읽지 못한다.

SET search_path = zeekad;

CREATE TABLE asset_observation (
    capture_id   text NOT NULL,
    asset_id     inet NOT NULL,
    kind         text NOT NULL CHECK (kind IN ('kerberos_machine', 'kerberos_user', 'ntlm_hostname', 'ntlm_user')),
    value        text NOT NULL,
    source_log   text NOT NULL,                  -- 예: kerberos.log
    observations integer NOT NULL CHECK (observations > 0),
    first_seen   timestamptz NOT NULL,
    last_seen    timestamptz NOT NULL,
    PRIMARY KEY (capture_id, asset_id, kind, value)
);

CREATE TABLE incident_evidence (
    job_id           bigint NOT NULL,
    incident_id      text NOT NULL,
    evidence_version text NOT NULL,              -- 예: evidence.v1 (요약 규칙 버전)
    connection_count integer NOT NULL,
    evidence         jsonb NOT NULL,
    built_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, incident_id),
    FOREIGN KEY (job_id, incident_id) REFERENCES incident ON DELETE CASCADE
);

GRANT SELECT, INSERT, UPDATE, DELETE ON asset_observation, incident_evidence TO zeekad_worker;
GRANT SELECT ON asset_observation, incident_evidence TO zeekad_api;

-- 대시보드 계약(docs/data-contract-v1.md). 열 이름은 ECS 이름의 밑줄 표기, 프로젝트 고유 값은 zeekad_ 접두사.
CREATE SCHEMA dashboard AUTHORIZATION zeekad_owner;

CREATE VIEW dashboard.scoring_jobs AS
SELECT j.job_id, j.capture_id, j.bundle_id, j.status, j.started_at, j.finished_at, j.error,
       (SELECT count(*) FROM incident i WHERE i.job_id = j.job_id) AS incident_count
FROM scoring_job j;

CREATE VIEW dashboard.model_bundles AS
SELECT bundle_id, registry_name, registry_version, manifest_sha256, registered_at,
       (SELECT jsonb_object_agg(m->>'name', (m->>'threshold')::double precision)
        FROM jsonb_array_elements(manifest->'models') m) AS thresholds
FROM model_bundle;

-- 완료된 작업의 결합 큐. 사건마다 근거 요약 수와 관측된 자산 이름을 붙인다.
CREATE VIEW dashboard.incident_queue AS
SELECT i.job_id, j.capture_id, j.bundle_id, i.queue_rank, i.incident_id,
       host(i.asset_id) AS host_ip, i.role AS zeekad_role,
       i.first_start AS event_start, i.last_end AS event_end,
       i.picked_by AS zeekad_picked_by, i.also_flagged_by AS zeekad_also_flagged_by,
       e.connection_count,
       (SELECT array_agg(DISTINCT o.value ORDER BY o.value) FROM asset_observation o
        WHERE o.capture_id = j.capture_id AND o.asset_id = i.asset_id
          AND o.kind IN ('kerberos_machine', 'ntlm_hostname')) AS host_name
FROM incident i
JOIN scoring_job j ON j.job_id = i.job_id AND j.status = 'succeeded'
LEFT JOIN incident_evidence e ON e.job_id = i.job_id AND e.incident_id = i.incident_id;

-- 사건별 모델 점수: 사건 창에서 각 모델의 최고 점수, 임계값 이상 창 수. 모델끼리 점수 척도는 다르다(DD-009).
CREATE VIEW dashboard.incident_model_scores AS
SELECT i.job_id, i.incident_id, s.model_name AS zeekad_model,
       max(s.score) AS max_score, count(*) FILTER (WHERE s.is_candidate) AS candidate_windows, count(*) AS windows
FROM incident i
JOIN scoring_job j ON j.job_id = i.job_id AND j.status = 'succeeded'
JOIN incident_window w ON w.job_id = i.job_id AND w.incident_id = i.incident_id
JOIN window_score s ON s.job_id = i.job_id AND s.asset_id = i.asset_id AND s.role = i.role
                   AND s.window_start = w.window_start
GROUP BY i.job_id, i.incident_id, s.model_name;

CREATE VIEW dashboard.asset_names AS
SELECT capture_id, host(asset_id) AS host_ip, kind AS zeekad_name_kind, value AS zeekad_name,
       source_log AS zeekad_source_log, observations, first_seen, last_seen
FROM asset_observation;

GRANT USAGE ON SCHEMA dashboard TO dashboard_ro, zeekad_api;
GRANT SELECT ON ALL TABLES IN SCHEMA dashboard TO dashboard_ro, zeekad_api;
