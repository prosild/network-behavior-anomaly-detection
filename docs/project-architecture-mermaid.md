# NBAD 프로젝트 구조도 (2026-11-13 기준, 당시 이름 `zeek_AD`)

현재 코드베이스와 [stage-4-progress.md](stage-4-progress.md), [stage-5-progress.md](stage-5-progress.md), [session-handoff.md](session-handoff.md) 기준으로 정리한 시스템 파이프라인과 PostgreSQL DB 구조입니다.

- 실선(녹색): 구현·검증 완료
- 점선(노랑): 진행 중
- 점선(회색): 예정 또는 별도 프로젝트

---

## 1. 전체 파이프라인 및 서비스 구조

```mermaid
flowchart TB
    classDef done fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
    classDef wip fill:#fff8e1,stroke:#f57f17,color:#e65100,stroke-dasharray:5 5
    classDef todo fill:#f5f5f5,stroke:#616161,color:#424242,stroke-dasharray:5 5

    subgraph S0_2["단계 0~2: 데이터 수집 및 전처리 (완료)"]
        RAW["CIC-IDS-2017 PCAP 5개 (읽기 전용)"]:::done
        ZEEK["Zeek 로그 생성 (scripts/run_zeek.py)"]:::done
        SYN["합성 APT 5종 주입 (scripts/build_synthetic_zeek.py)"]:::done
        SILVER["Silver 정제 conn (_write_ts 기준, build_silver_conn.py)"]:::done
        GOLD["Gold v2 42개 특징 5분 창 (build_gold_v2.py)"]:::done
        SEQ["Transformer 시퀀스 (build_sequences.py)"]:::done
        GRAPH["TGN 이벤트 그래프 (build_tgn_events.py, build_tgn_dataset.py)"]:::done

        RAW --> ZEEK
        ZEEK --> SYN
        ZEEK --> SILVER
        SYN --> SILVER
        SILVER --> GOLD
        GOLD --> SEQ
        ZEEK --> GRAPH
        SYN --> GRAPH
    end

    subgraph S3["단계 3: 모델 학습 및 결합 평가 (완료)"]
        TAIL["꼬리 희귀도 v2 (scripts/run_baselines.py)"]:::done
        TRANS["자기지도 Transformer v2 (scripts/run_transformer.py)"]:::done
        TGN["TGN recon 모델 (scripts/run_tgn.py)"]:::done
        FUSION["순위 번갈아 합치기 결합 v1 (scripts/run_fusion.py, DD-009)"]:::done
        MLFLOW["MLflow Tracking 및 Registry (zeekad-fusion v1 @champion)"]:::done

        GOLD --> TAIL
        SEQ --> TRANS
        GRAPH --> TGN
        TAIL --> FUSION
        TRANS --> FUSION
        TGN --> FUSION
        TAIL --> MLFLOW
        TRANS --> MLFLOW
        TGN --> MLFLOW
    end

    subgraph S4["단계 4: 추론, 저장, 근거 API (완료)"]
        BUNDLE["배포 묶음 FusionBundle (scripts/build_bundle.py)"]:::done
        WORKER["추론 Worker (scripts/run_worker.py, 장애복구 9/9 통과)"]:::done
        EVID["근거·자산명 생성기 (scripts/build_evidence.py)"]:::done
        PG[("PostgreSQL 17 + pgvector (deploy/compose.yaml, 127.0.0.1:55432)")]:::done
        API["근거 조회 FastAPI (scripts/run_api.py, 127.0.0.1:8000)"]:::done

        MLFLOW --> BUNDLE
        BUNDLE --> WORKER
        GOLD --> WORKER
        GRAPH --> WORKER
        WORKER --> PG
        ZEEK --> EVID
        PG --> EVID
        EVID --> PG
        PG --> API
    end

    subgraph S5["단계 5: RAG 및 보고서 에이전트 (진행 중·예정)"]
        CORPUS["ATT&CK 20.1 기법 706건 적재 (build_attack_corpus.py)"]:::done
        EMBED["임베딩 비교 및 BM25·벡터·혼합 검색 (query-set.v1.json)"]:::wip
        LG["LangGraph 흐름 (보고서 생성·상태 열림/확인중/종료)"]:::todo
        LLM["LLM/템플릿 보고서 (허용 필드만 입력, 호스트명·사용자명 제외)"]:::todo
        JEV["Jev 판단 게이트 및 알림 억제 (60분 병합·30분 간격)"]:::todo
        SLACK["Slack 알림 (초기 파일 dry-run)"]:::todo

        CORPUS --> PG
        PG --> EMBED
        PG --> LG
        EMBED --> LG
        LG --> LLM
        LLM --> JEV
        JEV --> SLACK
        JEV --> PG
    end

    subgraph EXT["단계 7 및 외부 연계 (예정·별도)"]
        ROLLBACK["Compose 통합 및 모델 교체·롤백 시연 (단계 7)"]:::todo
        JAVA["Spring Boot 관리자 대시보드 (별도 Java 프로젝트)"]:::todo

        PG -. "dashboard 스키마 뷰 5개 (dashboard_ro)" .-> JAVA
        API -. "REST API (docs/data-contract-v1.md)" .-> JAVA
        BUNDLE -. "버전 전환" .-> ROLLBACK
    end
```

---

## 2. PostgreSQL DB 스키마 및 계정 권한 구조

단일 PostgreSQL 인스턴스(`pgvector/pgvector:0.8.1-pg17`) 내부의 DB·스키마·계정 분리 구조입니다([001_core.sql](../db/migrations/001_core.sql), [002_evidence_dashboard.sql](../db/migrations/002_evidence_dashboard.sql), [003_rag.sql](../db/migrations/003_rag.sql)).

```mermaid
flowchart LR
    classDef role fill:#e3f2fd,stroke:#1565c0,color:#0d47a1
    classDef db fill:#f3e5f5,stroke:#6a1b9a,color:#4a148c

    subgraph ROLES["DB 역할 (접근 제어)"]
        R_OWN["zeekad_owner (마이그레이션 소유)"]:::role
        R_WRK["zeekad_worker (읽기·쓰기)"]:::role
        R_API["zeekad_api (읽기 전용)"]:::role
        R_DSH["dashboard_ro (뷰 읽기 전용)"]:::role
        R_MLF["mlflow (MLflow 백엔드 전용)"]:::role
    end

    subgraph DB_ML["mlflow DB"]
        T_ML["MLflow Tracking / Model Registry 표"]:::db
    end

    subgraph DB_ZK["zeekad DB"]
        subgraph SC_ZK["zeekad 스키마 (단계 4)"]
            T_CORE["model_bundle / scoring_job / window_score / incident / incident_window"]:::db
            T_EVID["asset_observation / incident_evidence"]:::db
        end

        subgraph SC_DSH["dashboard 스키마 (단계 4 뷰 5개)"]
            V_DSH["scoring_jobs / model_bundles / incident_queue / incident_model_scores / asset_names"]:::db
        end

        subgraph SC_RAG["rag 스키마 (단계 5a)"]
            T_RAG["attack_document (706건) / document_embedding (vector)"]:::db
        end
    end

    R_MLF -->|"소유"| T_ML
    R_OWN -->|"DDL 적용"| SC_ZK
    R_OWN -->|"DDL 적용"| SC_DSH
    R_OWN -->|"DDL 적용"| SC_RAG

    R_WRK -->|"SELECT/INSERT/UPDATE/DELETE"| T_CORE
    R_WRK -->|"SELECT/INSERT/UPDATE/DELETE"| T_EVID
    R_WRK -->|"SELECT/INSERT/UPDATE/DELETE"| T_RAG

    R_API -->|"SELECT"| T_CORE
    R_API -->|"SELECT"| T_EVID
    R_API -->|"SELECT"| V_DSH
    R_API -->|"SELECT"| T_RAG

    R_DSH -->|"SELECT 전용 (원본 표 차단)"| V_DSH
```

---

## 3. 구현 현황 요약

- **완료(단계 0\~4):** Zeek v2 로그 처리, 합성 APT 5종 주입, Gold v2 + 시퀀스 + TGN 그래프 생성, 세 모델 평가 및 결합 v1([DD-009](design-decisions/DD-009-rank-interleave-fusion.md)), MLflow PostgreSQL 백엔드 이전, `zeekad-fusion` v1 등록, 추론 worker(작업 8개·장애 복구 9/9 통과), `incident_evidence`·`asset_observation`·FastAPI 근거 API(12/12 통과) 및 대시보드 뷰 계약([data-contract-v1.md](data-contract-v1.md)) 완료.
- **진행 중(단계 5a):** `rag.attack_document` 706건 적재 완료([build_attack_corpus.py](../scripts/build_attack_corpus.py)), [query-set.v1.json](../configs/rag/query-set.v1.json) 초안 상태. 다음은 질의 세트 확정 후 임베딩 비교 및 검색 평가.
- **예정(단계 5b·7):** LangGraph(상태 흐름·보고서·Jev·Slack dry-run), Docker Compose 통합 및 모델 교체·롤백 시연, 별도 Java 대시보드 프롬프트 생성([java-admin-dashboard-requirements.md](java-admin-dashboard-requirements.md)).
