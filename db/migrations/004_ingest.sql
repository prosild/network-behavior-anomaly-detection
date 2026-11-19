-- 004. 파일 단위 자동 파이프라인의 처리 기록(DD-012).
--
-- ingest_file: 수신 폴더에 들어온 PCAP 하나 = 한 행. 같은 내용(sha256)은 한 번만 처리한다.
--   status 흐름: received → zeek_done → (다음 단위에서) pipeline_done. 실패하면 failed와 error(예외 종류·짧은 문장).
--   capture_id: 첫 패킷의 UTC 날짜로 정한 그날의 캡처(예: lab-20261201). 그날 파일을 모아 다시 계산한다.
SET search_path = zeekad;

CREATE TABLE ingest_file (
    file_sha256      char(64) PRIMARY KEY,
    file_name        text NOT NULL,
    size_bytes       bigint NOT NULL,
    first_packet_at  timestamptz,
    last_packet_at   timestamptz,
    packets          bigint,
    capture_id       text,
    zeek_run_dir     text,                         -- 프로젝트 기준 상대 경로
    status           text NOT NULL CHECK (status IN ('received', 'zeek_done', 'pipeline_done', 'failed')),
    error            text,
    received_at      timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ingest_file_capture ON ingest_file (capture_id, first_packet_at);

GRANT SELECT, INSERT, UPDATE ON ingest_file TO zeekad_worker;
GRANT SELECT ON ingest_file TO zeekad_api;
