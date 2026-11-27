# 데이터 계약 v1: Java 관리자 대시보드가 읽는 것

- 작성일: 2026-11-12. 결정: [DD-005](design-decisions/DD-005-deadline-scope.md)(단계 4에서 계약 고정), [DD-010](design-decisions/DD-010-ecs-enrichment-incident-lifecycle.md)(ECS 이름, 자산 정보)
- 정의: [db/migrations/002_evidence_dashboard.sql](../db/migrations/002_evidence_dashboard.sql). 확인: [scripts/check_api.py](../scripts/check_api.py)
- 바꾸려면 v2를 만든다. 뷰의 열을 지우거나 뜻을 바꾸지 않는다(추가만 한다).
- **v2가 나왔다:** [데이터 계약 v2](data-contract-v2.md)(보고서·전송 판단·Slack·사건 상태, 2026-11-17).

## 접속

| 항목 | 값 |
| --- | --- |
| 서버 | PostgreSQL 17, `127.0.0.1:55432`(이 PC 안에서만) |
| DB | `zeekad` |
| 계정 | `dashboard_ro`. 비밀번호는 `deploy/.env`의 `DASHBOARD_RO_PASSWORD`. Java 쪽은 환경 변수로 받는다(코드·Git에 넣지 않는다) |
| 권한 | `dashboard` 스키마의 뷰 SELECT만. 원래 표(`zeekad.*`)는 읽지 못한다. 쓰기 권한 없음 |

대시보드에 쓰기 기능(사건 상태 변경 등)이 필요해지면 별도 계정과 함수로 준다(단계 5 사건 상태 흐름, DD-010).

## 이름 규칙

- ECS(Elastic Common Schema) 이름을 밑줄로 쓴다: `host_ip` = `host.ip`, `event_start` = `event.start`.
- 이 프로젝트만의 값은 `zeekad_` 접두사다(`zeekad_role`, `zeekad_picked_by`).
- 시각은 모두 `timestamptz`(UTC)다. 캡처 시각은 2017년 7월이다(재생 자료).

## 뷰

### `dashboard.incident_queue` — 조사 큐(결합 v1, DD-009)

완료(succeeded)된 작업의 사건만 나온다. 하루(캡처) 큐는 `job_id`로 묶고 `queue_rank` 순으로 본다.

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `job_id` | bigint | 채점 작업. 캡처 하나 × 입력 × 모델 묶음 |
| `capture_id` | text | 예: `cic17-wed`, `syn1-tue`(합성 APT 주입 캡처) |
| `bundle_id` | text | 모델 묶음(MLflow Registry 이름/버전), 예: `zeekad-fusion/1` |
| `queue_rank` | integer | 그날 조사 순서(1부터) |
| `incident_id` | text | `capture|asset|role|first_start(epoch)` |
| `host_ip` | text | 사건의 자산(ECS `host.ip`) |
| `zeekad_role` | text | `originator`(자산이 연결을 시작) 또는 `responder`(자산이 연결을 받음) |
| `event_start`, `event_end` | timestamptz | 사건 창 범위(5분 창 단위, 최대 30분) |
| `zeekad_picked_by` | text | 이 사건을 큐에 넣은 모델: `tgn_recon`, `tail_rarity_v2`, `transformer_v2` |
| `zeekad_also_flagged_by` | text[] | 같은 사건을 겹쳐 꼽은 다른 모델 |
| `connection_count` | integer | 사건 창에서 그 자산·역할의 연결 수 |
| `host_name` | text[] | Zeek에서 관측한 이름(kerberos 기계 계정, ntlm 호스트명). 없으면 null |

### `dashboard.incident_model_scores` — 사건별 모델 점수

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `job_id`, `incident_id` | | 사건 키 |
| `zeekad_model` | text | 모델 이름 |
| `max_score` | double | 사건 창에서 그 모델의 최고 점수. **모델끼리 척도가 달라 서로 비교하지 않는다** |
| `candidate_windows` | bigint | 그 모델 임계값 이상인 창 수 |
| `windows` | bigint | 사건 창 수 |

임계값은 `dashboard.model_bundles.thresholds`에 있다.

### `dashboard.asset_names` — 자산 관측 이름

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `capture_id`, `host_ip` | text | 어느 캡처의 어느 자산 |
| `zeekad_name_kind` | text | `kerberos_machine`, `kerberos_user`, `ntlm_hostname`, `ntlm_user` |
| `zeekad_name` | text | 로그에 나온 값 그대로 |
| `zeekad_source_log` | text | `kerberos.log` 또는 `ntlm.log` |
| `observations`, `first_seen`, `last_seen` | | 관측 수와 처음·마지막 시각 |

**사용자 이름(`kerberos_user`, `ntlm_user`)과 IP는 개인정보가 될 수 있다.** 화면 마스킹과 원문 열람 권한은 대시보드 쪽 정책으로 정한다([요구사항](java-admin-dashboard-requirements.md)).

### `dashboard.scoring_jobs`, `dashboard.model_bundles` — 운영 상태

| 뷰 | 열 |
| --- | --- |
| `scoring_jobs` | `job_id`, `capture_id`, `bundle_id`, `status`(`running`·`succeeded`·`failed`), `started_at`, `finished_at`, `error`, `incident_count` |
| `model_bundles` | `bundle_id`, `registry_name`, `registry_version`, `manifest_sha256`, `registered_at`, `thresholds`(jsonb, 모델 → 임계값) |

`running`이 오래 남은 작업은 worker가 commit 전에 멈춘 것이다. 결과는 남지 않고 다음 실행이 이어받는다([단계 4 진행 기록](stage-4-progress.md) 네 번째 작업).

## 근거 조회 API(분석 화면용)

`python scripts/run_api.py` → `http://127.0.0.1:8000/docs`. 계정은 읽기 전용 `zeekad_api`다.

| 경로 | 내용 |
| --- | --- |
| `GET /api/v1/jobs` | 작업 목록 |
| `GET /api/v1/captures/{capture_id}/queue?limit=10` | 그 캡처 최신 완료 작업의 큐 |
| `GET /api/v1/jobs/{job_id}/incidents/{rank}` | 사건 근거: 모델별 점수·임계값, 관측된 자산 이름(출처 포함), 연결 요약(`evidence.v1`) |

`evidence.v1`(ECS 이름의 JSON): `host.ip`, `event.start/end`, `connection_count`, `network.transport/protocol/bytes`, `zeek_conn_state`, `peers.top`, `destination_ports.top`, `protocol_logs`(dns·http·tls·ssh·ftp·smb·kerberos·dce_rpc·ntlm 수), `representative_connections`(최대 10개, `zeek.uid`·`source`·`destination`·`network`), `limits`.

`limits`는 근거를 만들 때(작업마다) 함께 저장한 zeek_AD의 한국어 문장이다(`zeek_ad/evidence.py`의 `LIMITS`). zeek_AD의 용어("연결", "페이로드 바이트가 … 큰(부푼)")로 쓰여 화면 용어와 다를 수 있고, 문장을 고쳐도 이미 저장된 근거는 바뀌지 않는다. 화면에서 바꿔 보여 줄 때는 문장이 아니라 문장이 가리키는 키(`network.zeekad_payload_bytes_inflated`)를 기준으로 한다(2026-11-27).
- 바이트는 관측한 IP 바이트다. Zeek 페이로드 바이트가 부푼 연결 수는 `network.zeekad_payload_bytes_inflated`.
- DNS 질의·HTTP URI·SNI 같은 문자열은 v1에 없다(비신뢰 입력, 설계 9.1절).
- 원본 연결 전체는 Parquet 이벤트 표에 있고, 대표 연결의 `zeek.uid`로 찾는다.
