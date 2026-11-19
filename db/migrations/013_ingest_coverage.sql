-- 013. 수집 파일이 덮은 시간(DD-016).
--
-- 배경: 캡처 경계를 패킷 시각 최댓값으로 잡았다. 조용한 실습망에서 공격이 09:49:49에 끝나면 09:45~09:50 창은
-- "09:50까지 관측했는지 모른다"고 보아 capture_edge(채점 큐에서 빠짐)가 됐다(2026-11-18 nmap 시험).
-- 수집기(scripts/capture_rotate.sh)는 시계 경계마다 파일을 닫고 덮은 시간을 이름에 넣는다.
-- 수신 처리(zeek_ad.ingest)가 그 값을 여기에 남기고, 다시 계산이 캡처 경계의 끝으로 쓴다(zeek_ad.live_capture).
-- 이름에 덮은 시간이 없는 파일(손으로 넣은 파일, 예전 수집 파일)은 두 열이 NULL이고 예전처럼 패킷 시각만 쓴다.
SET search_path = zeekad;

ALTER TABLE ingest_file
    ADD COLUMN covered_from timestamptz,           -- 수집기가 이 파일을 쓰기 시작한 시각(초 아래 버림)
    ADD COLUMN covered_to   timestamptz,           -- 수집기가 이 파일을 닫기 직전 시각(초 아래 버림). 이때까지 관측했다
    ADD CONSTRAINT ingest_file_coverage CHECK (
        (covered_from IS NULL AND covered_to IS NULL) OR (covered_to > covered_from));
