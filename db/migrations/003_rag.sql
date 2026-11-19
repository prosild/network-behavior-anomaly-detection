-- 003. RAG 문서 표(단계 5a, DD-002 2절). ATT&CK 기법 문서와 임베딩.
--
-- attack_document: 기법 하나 = 문서 하나. 설명·완화책·사용 그룹은 사용자 RAG 실습 DB 본문을 그대로 쓰고(설계 질문 기록 Q37),
--                  탐지 절은 ATT&CK 20.1 원본의 detection strategy·analytic으로 다시 만든다.
-- document_embedding: 임베딩 모델마다 한 행. 문서가 706개뿐이라 인덱스 없이 전체를 정확히 비교한다(근사 검색 오차가 없다).
-- pgvector 확장(public.vector)은 superuser가 만들었다(deploy/postgres/init/02-extensions.sh).

CREATE SCHEMA rag AUTHORIZATION zeekad_owner;

CREATE TABLE rag.attack_document (
    attack_id       text PRIMARY KEY,               -- 예: T1021.002
    stix_id         text NOT NULL UNIQUE,
    attack_version  text NOT NULL,                  -- 예: 20.1
    name            text NOT NULL,
    tactics         text[] NOT NULL,
    platforms       text[] NOT NULL,
    is_subtechnique boolean NOT NULL,
    url             text,
    data_components text[] NOT NULL,                -- 탐지에 쓰는 데이터 구성 요소(예: Network Traffic Flow)
    detection       text NOT NULL,                  -- 다시 만든 탐지 절(마크다운)
    document        text NOT NULL,                  -- 최종 본문: 실습 본문의 빈 탐지 절을 detection으로 바꾼 것
    source          jsonb NOT NULL                  -- 출처: 실습 DB 스냅샷·STIX 파일 해시
);

CREATE TABLE rag.document_embedding (
    attack_id   text NOT NULL REFERENCES rag.attack_document ON DELETE CASCADE,
    model_id    text NOT NULL,                      -- 예: gemini-embedding-001@768
    dims        integer NOT NULL,
    text_sha256 char(64) NOT NULL,                  -- 임베딩한 글의 해시(글이 바뀌면 다시 만든다)
    embedding   public.vector NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (attack_id, model_id),
    CHECK (vector_dims(embedding) = dims)
);

GRANT USAGE ON SCHEMA rag TO zeekad_worker, zeekad_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON rag.attack_document, rag.document_embedding TO zeekad_worker;
GRANT SELECT ON rag.attack_document, rag.document_embedding TO zeekad_api;
