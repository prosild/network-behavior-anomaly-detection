-- 001. 추론 결과 저장 표(설계 7.1·7.2절, 단계 4).
-- zeekad_owner로 실행한다(scripts/db_migrate.py). 한 파일이 한 트랜잭션이다.
--
-- 흐름: 배포 묶음(model_bundle) → 채점 작업(scoring_job, 캡처 하나 × 입력 × 묶음)
--       → 창 점수(window_score) → 사건 큐(incident, incident_window).
-- 작업 하나의 점수·사건은 한 트랜잭션으로 쓰고, 마지막에 작업을 succeeded로 바꾼다.
-- 그래서 succeeded가 아닌 작업의 결과는 읽지 않는다.

SET search_path = zeekad;

-- MLflow Registry 모델 버전과 연결한 배포 묶음(설계 8절: 모델 + 전처리 + 특징 스키마 + 임계값 + 사건 정책).
CREATE TABLE model_bundle (
    bundle_id        text PRIMARY KEY,               -- 예: 'zeekad-fusion/1' (Registry 이름/버전)
    registry_name    text NOT NULL,
    registry_version integer NOT NULL,
    manifest_sha256  char(64) NOT NULL,              -- 묶음 manifest 파일 해시
    manifest         jsonb NOT NULL,
    registered_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (registry_name, registry_version)
);

-- 채점 작업. 같은 캡처·입력·묶음은 작업 하나다(중복 실행 방지).
CREATE TABLE scoring_job (
    job_id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    capture_id            text NOT NULL,
    input_manifest_sha256 char(64) NOT NULL,         -- 입력(Gold·그래프) manifest 해시
    bundle_id             text NOT NULL REFERENCES model_bundle,
    status                text NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    started_at            timestamptz NOT NULL DEFAULT now(),
    finished_at           timestamptz,
    error                 text,
    UNIQUE (capture_id, input_manifest_sha256, bundle_id)
);

-- 모델별 창 점수. 점수는 모델 안에서만 비교한다(모델끼리 척도가 다르다, DD-009).
CREATE TABLE window_score (
    job_id       bigint NOT NULL REFERENCES scoring_job ON DELETE CASCADE,
    model_name   text NOT NULL,
    asset_id     inet NOT NULL,
    role         text NOT NULL CHECK (role IN ('originator', 'responder')),
    window_start timestamptz NOT NULL,
    split        text NOT NULL,
    score        double precision NOT NULL,
    is_candidate boolean NOT NULL,                   -- 그 모델 임계값 이상
    PRIMARY KEY (job_id, model_name, asset_id, role, window_start)
);

-- 결합 큐(DD-009)의 사건. queue_rank가 하루 조사 순서다.
CREATE TABLE incident (
    job_id          bigint NOT NULL REFERENCES scoring_job ON DELETE CASCADE,
    incident_id     text NOT NULL,                   -- capture|asset|role|first_start(epoch 초)
    queue_rank      integer NOT NULL CHECK (queue_rank >= 1),
    asset_id        inet NOT NULL,
    role            text NOT NULL CHECK (role IN ('originator', 'responder')),
    first_start     timestamptz NOT NULL,
    last_end        timestamptz NOT NULL,
    picked_by       text NOT NULL,                   -- 이 사건을 큐에 넣은 모델
    also_flagged_by text[] NOT NULL DEFAULT '{}',    -- 같은 사건을 겹쳐 꼽아 건너뛴 모델
    model_score     double precision NOT NULL,       -- picked_by 모델의 사건 점수
    PRIMARY KEY (job_id, incident_id),
    UNIQUE (job_id, queue_rank),
    CHECK (last_end > first_start)
);

-- 사건을 이루는 창(picked_by 모델의 창).
CREATE TABLE incident_window (
    job_id       bigint NOT NULL,
    incident_id  text NOT NULL,
    window_start timestamptz NOT NULL,
    PRIMARY KEY (job_id, incident_id, window_start),
    FOREIGN KEY (job_id, incident_id) REFERENCES incident ON DELETE CASCADE
);

-- 권한: worker는 쓰고, API는 읽기만 한다. 대시보드(dashboard_ro)는 뷰를 만들 때 따로 준다.
GRANT USAGE ON SCHEMA zeekad TO zeekad_worker, zeekad_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON model_bundle, scoring_job, window_score, incident, incident_window
    TO zeekad_worker;
GRANT SELECT ON model_bundle, scoring_job, window_score, incident, incident_window TO zeekad_api;
