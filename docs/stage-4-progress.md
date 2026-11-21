# 단계 4 진행 기록

단계 4 범위(설계 10절, DD-005 일정 수정 절): MLflow Registry 배포 묶음, 추론 worker, PostgreSQL, 근거 조회 API, Java 대시보드 데이터 계약. 완료 기준은 입력부터 사건까지 추적, 배치 중복·쓰기 중 장애 복구, 실제 모델 버전 확인이다.

작은 단위 순서:
1. PostgreSQL 기동과 핵심 표(이 기록의 첫 작업)
2. 배포 묶음 manifest와 MLflow Registry 등록(결합 v1 = TGN recon + 꼬리 희귀도 v2 + Transformer v2)
3. 추론 worker: 입력 manifest 확인 → 묶음 적재(alias를 버전으로 고정) → 점수 → 결합 큐 → 한 트랜잭션 저장
4. 장애 복구 시험: 같은 작업 재실행, 쓰기 중 중단, commit 전후 중단
5. 근거 조회 API(FastAPI)와 대시보드용 읽기 전용 뷰·계정(Java 데이터 계약)

## 첫 작업: PostgreSQL 기동과 핵심 표(2026-11-11)

### 구성
- [deploy/compose.yaml](../deploy/compose.yaml): `pgvector/pgvector:0.8.1-pg17`(PostgreSQL 17.8, 이미지 id `sha256:3e8b3adf…`). 단계 5a RAG가 같은 서버의 pgvector를 쓴다.
  - 포트는 `127.0.0.1:55432`에만 연다. 같은 PC의 다른 프로젝트(supabase)가 54322를 쓰고 있어 피했다.
  - 데이터는 Docker 이름 있는 볼륨 `zeekad_pgdata`에 둔다. 컨테이너를 지워도 남는다.
- 비밀번호: [scripts/make_env.py](../scripts/make_env.py)가 `deploy/.env`(권한 600, `.gitignore`)를 무작위 값으로 만든다. 예시는 [deploy/.env.example](../deploy/.env.example). 코드에는 비밀번호가 없다.
- [deploy/postgres/init/01-roles-databases.sh](../deploy/postgres/init/01-roles-databases.sh): 처음 기동할 때 한 번 역할과 DB를 만든다.

| 역할 | 용도 | 권한 |
| --- | --- | --- |
| `zeekad_owner` | 표 만들기(마이그레이션) | `zeekad` DB·스키마 소유 |
| `zeekad_worker` | 추론 worker | 표 읽기·쓰기 |
| `zeekad_api` | 근거 조회 API | 표 읽기만 |
| `dashboard_ro` | Java 대시보드 | 지금은 없음. 5번에서 읽기 전용 뷰만 준다 |
| `mlflow` | MLflow 백엔드(옮길 때 쓴다) | `mlflow` DB 소유 |

- `zeekad`·`mlflow` DB의 기본 접속 권한(PUBLIC)을 없앴다. public 스키마에 아무나 표를 만들지 못한다. 앱 표는 `zeekad` 스키마에 있다.

### 표([db/migrations/001_core.sql](../db/migrations/001_core.sql))
- `model_bundle`(Registry 이름/버전, 묶음 manifest와 해시) → `scoring_job`(캡처 × 입력 manifest 해시 × 묶음, 유일) → `window_score`(모델별 창 점수, 후보 여부) → `incident`(결합 큐 순위, 뽑은 모델, 겹쳐 꼽은 모델) → `incident_window`.
- 작업 하나의 점수·사건은 한 트랜잭션으로 쓰고 마지막에 `succeeded`로 바꾼다. `succeeded`가 아닌 작업은 읽지 않는다. 복구 규칙의 바탕이다(4번에서 시험).
- [scripts/db_migrate.py](../scripts/db_migrate.py): 번호 순서로 적용, 파일 하나 = 트랜잭션 하나, `schema_migrations`에 해시 기록. 적용한 파일이 바뀌면 멈춘다.
- [zeek_ad/db.py](../zeek_ad/db.py): 역할별 접속. 비밀번호는 `deploy/.env` 또는 환경 변수에서 읽는다.

### 검사(Claude 실행)
- 기동 후 healthy, 초기화 로그에 역할 5개·DB 2개·스키마 생성.
- 마이그레이션: 첫 실행 `applied 001_core.sql`, 두 번째 실행 `skip`(같은 해시).
- 권한: worker 쓰기 성공(롤백), api 쓰기 거부(`permission denied`), api 읽기 성공, dashboard_ro는 스키마 접근 불가, worker의 `mlflow` DB 접속 거부.

### 남은 결정
- MLflow 백엔드를 PostgreSQL로 옮기는 일은 두 번째 작업에서 했다.

## 두 번째 작업: MLflow 백엔드 이전과 배포 묶음 Registry 등록(2026-11-12)

### MLflow 백엔드: SQLite → PostgreSQL `mlflow` DB(설계 7.1절)
- [scripts/migrate_mlflow_to_pg.py](../scripts/migrate_mlflow_to_pg.py): MLflow에는 백엔드 이전 도구가 없다. 같은 MLflow 버전(표 버전 `dc11669786a5`)이 만든 표라 행을 그대로 복사했다(한 트랜잭션).
  - 옮긴 행: 실험 2, run 31(지운 run 9 포함), metric 1,532, 최신 metric 722, param 226, tag 239.
  - 대조: MLflow API로 두 백엔드를 읽어 활성 run 22개의 param·tag·metric·metric 이력 전체·artifact 경로가 모두 같다(불일치 0).
  - artifact는 그대로 `outputs/mlflow/artifacts`(파일)다. SQLite 파일은 백업으로 남겼다. 코드는 더 이상 읽지 않는다.
- [zeek_ad/experiment.py](../zeek_ad/experiment.py) `setup_mlflow`가 PostgreSQL을 쓴다. 접속 주소는 [zeek_ad/db.py](../zeek_ad/db.py) `mlflow_tracking_uri()`(비밀번호는 `deploy/.env`).

### 배포 묶음(설계 8절: 모델 + 전처리 + 특징 스키마 + 임계값 + 사건 정책 + 호환성)
- [zeek_ad/bundle.py](../zeek_ad/bundle.py) `FusionBundle`: MLflow pyfunc 모델 하나에 세 모델을 싣는다.
  - 꼬리 희귀도 v2: 특징별 정렬된 월요일 train 값(npz).
  - Transformer v2: 체크포인트 + 전처리(중앙값) + 표준화(평균·표준편차). 다시 적합한 값이 학습 때 시퀀스 manifest의 값과 같은지 확인한 뒤 담았다.
  - TGN recon: 학습 parameter + 인코딩(encoding.json). 다른 인코딩으로 만든 그래프는 거부한다(해시 대조).
  - 임계값 3개(각 평가 run의 보류 p95), 사건 정책(5분 창, 30분 상한, 동점 해시), 결합 규칙(fusion.v1.json).
  - `code_paths`로 `zeek_ad` 코드를 같이 싣는다. 패키지 버전은 고정 목록이다.
  - 메서드: `score_capture`(캡처 하나의 세 모델 창 점수), `build_queue`(모델별 큐 → 결합 큐), `predict`(캡처 행 표 → 창 점수 긴 표).
- [scripts/build_bundle.py](../scripts/build_bundle.py): 구성 요소 모으기 → manifest → 로컬 저장 → **다시 불러와 CIC 다섯 캡처의 창 점수를 원래 평가 run과 대조** → `--register`일 때만 등록.
  - 대조 결과: 세 모델 모두 최대 차이 0(창 집합도 같음). 실행 1분 23초.
  - 확인용 첫 실행(등록 안 함)의 출력 폴더는 지웠다.

### Registry
- 등록: `zeekad-fusion` 버전 1, alias `champion` → 1. 실험 `zeek-ad-stage4`, run `106125e7518743c7976016c2751d02c6`. 버전 태그: manifest 해시 `c81dc647…`, 재현 확인.
- 묶음 파일: `outputs/bundles/fusion_v1/20261112T004402Z/`(components, model, manifest.json).
- Registry에서 다시 받기 확인: alias `champion`을 버전 1로 풀고 `models:/zeekad-fusion/1`을 불러 화요일을 채점했다. 결합 큐 상위 5개의 출처가 단계 3 결합 평가 기록과 같다.

## 세 번째 작업: 추론 worker(2026-11-12)

### 코드
- [configs/worker/inputs.v1.json](../configs/worker/inputs.v1.json): 채점할 캡처 묶음(`cic`: 화\~금, `synthetic`: syn1 화\~금)과 입력 경로. 입력은 이미 만든 Gold v2·TGN 그래프다(배치 재생).
- [zeek_ad/worker.py](../zeek_ad/worker.py), [scripts/run_worker.py](../scripts/run_worker.py):
  1. 시작할 때 alias `champion`을 버전 번호로 풀어 고정하고 `models:/zeekad-fusion/<버전>`으로 받는다. 받은 manifest 해시를 Registry 태그와 대조한다. 묶음을 만든 코드와 지금 `zeek_ad` 코드의 해시가 다르면 멈춘다(worker는 이 저장소 코드를 import하기 때문이다).
  2. 트랜잭션 1: 작업 키(캡처 × 입력 해시 × 묶음)로 `scoring_job`을 만든다(running). 이미 succeeded면 건너뛴다. 입력 해시는 Gold manifest·그래프 manifest·캡처 경계 파일 해시로 만든다.
  3. 채점·결합 큐(트랜잭션 밖).
  4. 트랜잭션 2: 작업 행 잠금(`FOR UPDATE`) → 아직 succeeded가 아니면 창 점수(COPY)·사건·사건 창·succeeded 표시를 한 번에 commit. 두 worker가 같은 작업을 동시에 채점해도 먼저 commit한 쪽만 쓴다.
  5. 예외가 나면 결과 트랜잭션은 롤백되고, 작업을 failed와 오류 문구로 따로 기록한다. 다시 돌리면 running·failed 작업을 이어받는다.
- [scripts/verify_worker_db.py](../scripts/verify_worker_db.py): 읽기 전용 계정으로 DB의 결합 큐를 다시 읽어 단계 3 결합 평가와 같은 Recall@N인지 확인한다.

### 실행과 검사(Claude 실행)
- `python scripts/run_worker.py --set cic synthetic`: 작업 8개, 캡처당 15\~24초, 전체 2분 35초. 창 점수 40,182행(창 × 3모델), 사건 2,128개, 사건 창 2,921개.
- 추적 확인: DB에서 다시 읽은 큐가 단계 3 결합 평가(`outputs/eval/20261111T014619Z-fusion_v1`)와 8개 캡처 모두 사건 수·Recall@5/10/20/50이 같다(합성은 CIC 사건을 빼지 않은 전체 큐와 비교).
- 중복 방지: 같은 명령을 다시 돌리면 8개 모두 "이미 완료, 건너뜀". 행 수가 그대로다.
- 장애 복구(쓰기 중 중단, commit 전후 중단)는 다음 작업에서 시험한다.

## 네 번째 작업: worker 장애 복구 시험(2026-11-12)

### 방법
- 시험 DB `zeekad_test`를 따로 만들었다([deploy/postgres/create_test_db.sh](../deploy/postgres/create_test_db.sh) → `db_migrate.py --db zeekad_test`). 운영 DB와 같은 역할·표 구조이고 시험 데이터만 담는다.
- worker에 시험용 장애 지점을 넣었다(`ZEEKAD_FAULT` 환경 변수, [scripts/run_worker.py](../scripts/run_worker.py) `fault`).
  - `mid_write`: 창 점수를 COPY한 직후, `before_commit`: 모든 행을 쓴 뒤 commit 직전, `after_commit`: commit 직후.
  - 이 값이면 `os._exit`로 정리 코드 없이 프로세스를 끝낸다(전원이 나간 것과 비슷하다). `raise_<지점>`은 예외를 던져 정상 실패 경로를 시험한다.
- [scripts/test_worker_recovery.py](../scripts/test_worker_recovery.py): 화요일 작업 하나로 시나리오마다 표를 비우고 실행한다. 완료 결과는 운영 DB의 같은 작업과 사건 순서(순위·ID·뽑은 모델·겹친 모델)·행 수가 같아야 통과다.

### 결과: 9/9 통과(Claude 실행, 약 5분)

| 시나리오 | 중단 직후 | 다시 실행 |
| --- | --- | --- |
| A 창 점수 쓴 직후 종료 | 작업 running, 결과 0행 | 이어받아(resume) 완료, 운영과 같음 |
| B commit 직전 종료 | 작업 running, 결과 0행 | 이어받아 완료, 운영과 같음 |
| C commit 직후 종료 | 작업 succeeded, 결과 전부(창 점수 4,851, 사건 249, 사건 창 321) | "이미 완료, 건너뜀", 행 수 그대로(중복 0) |
| D 쓰는 중 예외 | 롤백, 작업 failed + 오류 문구, 결과 0행 | 이어받아 완료, 운영과 같음 |
| E worker 두 개 동시 실행 | 둘 다 채점, 한쪽만 commit | 다른 쪽은 행 잠금을 기다린 뒤 succeeded를 보고 쓰지 않음, 행 수 1배 |

- 해석: 결과는 commit 단위로만 보인다. 중간에 멈추면 아무것도 남지 않고, 작업 상태(running·failed)가 남아 다음 실행이 이어받는다. commit 뒤에 멈추면 다음 실행이 건너뛴다.
- 한계: 같은 PC의 단일 PostgreSQL에서 프로세스 종료만 시험했다. DB 서버 자체의 중단, 디스크 오류는 시험하지 않았다. Parquet 파일 쪽 원자성(임시 폴더 → 이름 바꾸기)은 단계 2\~3 빌드 스크립트의 규칙이다.

## 다섯 번째 작업: 근거 조회 API와 대시보드 데이터 계약(2026-11-12)

사용자가 수강 중인 보안 강의 원칙을 반영했다([DD-010](design-decisions/DD-010-ecs-enrichment-incident-lifecycle.md), 설계 질문 기록 Q39): ECS 필드 이름, Zeek 관측 기반 자산 이름.

### 표와 뷰([db/migrations/002_evidence_dashboard.sql](../db/migrations/002_evidence_dashboard.sql))
- `asset_observation`: Zeek kerberos `client`(기계 계정 `NAME$`·사용자)와 ntlm `hostname`·`username`. 출처 로그, 관측 수, 처음·마지막 시각. 점수 대상 자산만.
- `incident_evidence`: 사건 근거 요약(`evidence.v1`, ECS 이름 JSON)과 연결 수.
- `dashboard` 스키마 뷰 5개(`incident_queue`, `incident_model_scores`, `asset_names`, `scoring_jobs`, `model_bundles`). `dashboard_ro`는 이 뷰만 읽는다.

### 근거·자산 관측 작업([zeek_ad/evidence.py](../zeek_ad/evidence.py), [scripts/build_evidence.py](../scripts/build_evidence.py))
- worker 다음에 돈다. 자산 관측은 캡처 단위로 지우고 다시 쓰고, 근거는 작업 하나 = 트랜잭션 하나다. 근거가 이미 다 있으면 건너뛴다. 8개 작업 1분 25초.
- 근거 요약: 연결 수, 전송 계층·서비스 분포, 바이트, conn_state, 상위 상대 5개, 상위 목적지 포트 5개, 프로토콜 로그 수(dns·http·tls·ssh·ftp·smb·kerberos·dce_rpc·ntlm), 대표 연결 10개(상대별 첫 연결 → 시간순, 같은 입력이면 같은 결과), 한계 문구. DNS 질의·URI·SNI 같은 문자열은 넣지 않았다(비신뢰 입력, 설계 9.1절).
- 자산 관측 결과(수요일 예): 192.168.10.50 = `CIC-WEBSERVER$`, .8 = `MITACS-PC2`(ntlm)·`MITACS-PC2$`, .17 = `UBUNTU14-64$`, .51 = `UBUNTU12SRV$`. 사용자 계정도 나온다(예: 금요일 .12 `cic6@TESTBED1.CA`, 전체 154행). 개인정보라 대시보드 마스킹 정책 대상이다.
- 검사: 사건 2,128개 모두 근거의 연결 수가 Gold v2의 같은 창 `conn_count` 합과 같다(불일치 0).
- **발견한 데이터 문제:** Zeek `orig_bytes`·`resp_bytes`(TCP 시퀀스 번호로 계산)가 비정상 종료 연결에서 크게 부푼다. 수요일 1위 사건(192.168.10.50 responder, DoS) 창에서 724개 연결이 그렇고, 합계가 1.06TB로 나왔다. 실제 관측 IP 바이트(`orig_ip_bytes`) 합은 124MB다.
  - 근거 요약은 IP 바이트를 쓰고, 부푼 연결 수를 `network.zeekad_payload_bytes_inflated`로 따로 보인다.
  - 모델 입력(Gold `out_bytes_sum`·`in_bytes_sum`, TGN 수치)은 페이로드 바이트를 쓴다. 이미 동결한 모델이라 바꾸지 않는다. 포트폴리오 한계에 적는다(DoS 창의 바이트 특징이 실제보다 크다).

### 근거 조회 API([zeek_ad/api.py](../zeek_ad/api.py), [scripts/run_api.py](../scripts/run_api.py))
- FastAPI, 읽기 전용 계정 `zeekad_api`, `127.0.0.1:8000`. 경로 3개: 작업 목록, 캡처 큐, 사건 근거(모델별 최고 점수·임계값·임계값 이상 여부, 관측된 자산 이름과 출처, `evidence.v1`).
- 입력 검증: `capture_id`는 정규식, `limit` 1\~200, 값은 모두 파라미터 바인딩. DB 오류는 내부 문구 없이 503.
- [scripts/check_api.py](../scripts/check_api.py) 12/12 통과: 응답 형식, 수요일 1위 사건 근거, 잘못된 입력 422·404, `dashboard_ro`는 뷰 2,128행을 읽고 원래 표는 거부, `zeekad_api` 쓰기 거부.
- 패키지: fastapi 0.162.0, uvicorn 0.54.0, httpx 0.28.1을 [requirements.txt](../requirements.txt)에 직접 의존으로 적었다(이미 잠금 파일에 있던 버전).

### Java 데이터 계약
- [docs/data-contract-v1.md](data-contract-v1.md): 접속(계정·권한), 이름 규칙(ECS 밑줄 표기, `zeekad_` 접두사), 뷰별 열·타입·뜻, 개인정보 주의, API.

### 단계 4 완료 기준 대조(설계 10절)
- 입력부터 사건까지 추적: 입력 manifest 해시 → 작업 → 묶음(Registry 버전·manifest 해시) → 창 점수 → 사건 → 근거(uid). DB의 큐가 단계 3 평가와 같다(세 번째 작업).
- 배치 중복·쓰기 중 장애 복구: 네 번째 작업 9/9.
- 실제 모델 버전 확인: worker가 alias를 버전으로 고정하고 작업에 `bundle_id`를 남긴다. 교체·롤백 시연은 단계 7(11-16)이다.
