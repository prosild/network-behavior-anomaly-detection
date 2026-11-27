# 데이터 계약 v2: 단계 5b 결과(보고서·전송 판단·Slack·사건 상태)

- 작성일: 2026-11-17. [데이터 계약 v1](data-contract-v1.md)에 뷰를 **추가만** 했다. v1 뷰의 열과 뜻은 바뀌지 않는다.
- 정의: [008_incident_status.sql](../db/migrations/008_incident_status.sql)(상태 뷰·상태 변경 함수), [010_dashboard_v2.sql](../db/migrations/010_dashboard_v2.sql)(보고서·판단·Slack 뷰), [011_report_facts.sql](../db/migrations/011_report_facts.sql)(사실 목록·가명표 열), [012_incident_identity.sql](../db/migrations/012_incident_identity.sql)(v2.1: 사건 ID 기준 상태, 최신 큐 뷰)
- 관련 결정: [DD-001](design-decisions/DD-001-slack-delivery-jev-gate.md)(전송 판단 A단계), [DD-010](design-decisions/DD-010-ecs-enrichment-incident-lifecycle.md)(사건 상태), [DD-011](design-decisions/DD-011-gemini-decision-model.md)(판단 모델), [DD-014](design-decisions/DD-014-no-human-labels.md)
- 접속과 이름 규칙은 v1과 같다. 읽기는 `dashboard_ro`, 상태 변경은 `dashboard_rw`(아래 "쓰기")다.

## 한 사건에 붙는 것

```
incident_queue (v1) ── 사건 하나 = (job_id, incident_id)
 ├ incident_reports     보고서 1개(LLM 또는 템플릿)
 ├ send_decisions       전송 판단 1개(세 의견)
 ├ slack_deliveries     Slack 기록 0~3개(사건 알림, 상태 후속 알림)
 ├ incident_status      상태 1개(행이 없으면 open)
 ├ incident_status_history  상태 변경 이력 0개 이상
 └ analyst_review_queue 분석가 검토 요청 0~1개
```

- 보고서·판단·Slack 기록은 **전송 판단 대상 사건에만** 있다. 지금은 캡처마다 큐 상위 일부(평가 세트 60건)다. 나머지 사건은 v1 뷰만 있다. 화면에서는 "보고서 없음"으로 보여 준다.
- 모든 뷰는 `(job_id, incident_id)`로 조인한다. `incident_id`에는 자산 IP가 들어 있다(v1과 같다).

## 뷰

### `dashboard.incident_reports`: 사건 보고서

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `job_id`, `incident_id` | | 사건 키 |
| `zeekad_report_kind` | text | `llm`(LLM 보고서가 검증 통과) 또는 `template`(검증 실패·호출 실패로 규칙 템플릿으로 바꿈) |
| `zeekad_report_version` | text | `llm-report.v1` 또는 `template.v1` |
| `zeekad_input_version` | text | LLM 입력 형식, 예: `llm-input.v2` |
| `zeekad_report` | jsonb | 화면에 보일 보고서 본문(아래 구조) |
| `zeekad_verification_passed` | boolean | LLM 보고서 검증 결과. `false`면 kind가 `template`이다 |
| `zeekad_verification_reason` | text | 실패 이유: `verification`(숫자·가명·ATT&CK ID가 사실과 안 맞음), `call`(호출 실패) 등. 통과면 null |
| `zeekad_verification_problems` | jsonb | 걸린 항목 목록, 예: `[{"kind": "number_not_in_facts", "value": "2", "where": "possible_explanations[2]"}]` |
| `llm_model_requested`, `llm_model_version` | text | 요청한 모델과 실제 응답한 모델 버전(다를 수 있다. 예: 2026-11-20까지 요청 `gemini-3.7-flash`, 응답 `gemini-3.8-flash`. 2026-11-21부터 운영 요청도 `gemini-3.8-flash`, Q64) |
| `llm_seconds` | double | LLM 호출 시간(초) |
| `llm_input_tokens`, `llm_output_tokens`, `llm_thinking_tokens` | integer | 토큰 수. 호출 실패면 null |
| `llm_error` | text | 호출 오류 종류. 없으면 null |
| `zeekad_attack_candidates` | jsonb | 검색으로 찾은 ATT&CK 후보 `[{attack_id, name, tactics}]`. **가설이다.** 보고서의 `attack_ids`는 이 안에서만 나온다. `tactics`는 ATT&CK Enterprise 20.1의 짧은 이름이다. 이 판에는 `defense-evasion`이 없고, 그 ID(TA0005)를 이어받은 `stealth`와 새 전술 `defense-impairment`(TA0112)가 있다(검색 문서 706건 중 151건·57건, 2026-11-27 확인) |
| `zeekad_source_run` | text | 만든 실행(재현용). 예: `20261117T020850Z-eval`, `agent-graph.v1` |
| `created_at` | timestamptz | 만든 시각 |
| `zeekad_facts` | jsonb | 보고서를 쓸 때 LLM에 보낸 사실 목록 `[{id, name, value}]`. 가명·상대 초로 되어 있고 실제 IP는 없다 |
| `zeekad_pseudonyms` | jsonb | 가명표 `{"H": "192.168.10.50", "I1": "...", "X1": "..."}`. **실제 IP다.** DB에만 있고 LLM에는 보내지 않았다. 보관 기간·삭제 정책은 없다(Q84). 화면에서는 권한 있는 역할에만 보이길 권한다 |

`zeekad_report` 구조:

| 키 | LLM | 템플릿 | 뜻 |
| --- | --- | --- | --- |
| `observation_summary` | O | O | 한두 문장 요약 |
| `claims` | O | O | `[{claim, fact_ids}]`. 관측 사실 문장과 근거 사실 번호 |
| `possible_explanations` | O | O(빈 배열) | `[{explanation, fact_ids, attack_ids}]`. 가능한 해석(가설) |
| `send_recommendation` | O | **없음** | `{choice, reason, fact_ids}`. LLM의 전송 의견. 실제 전송 여부가 아니다 |
| `limitations`, `follow_up` | O | O | 한계, 추가로 확인할 것(문장 배열) |
| `report_version` | O | O | 위 열과 같다 |

- **글 속 `H`, `I1`, `X1`은 가명이다.** `H`는 사건 자산(`host_ip`), `I*`는 내부 상대, `X*`는 외부 상대다. LLM에 실제 IP를 보내지 않으려고 쓴다. 실제 주소는 근거 API의 `peers.top`·`representative_connections`에서 본다.
- `F01` 같은 사실 번호는 `zeekad_facts`의 `id`다. 화면에서는 주장 옆에 근거 사실(이름·값)을 펼쳐 보여 줄 수 있다.
- 가명을 실제 주소로 바꿔 보여 줄 때는 `zeekad_pseudonyms`를 쓴다. 예: 주장 "외부 피어 X1과의 연결이 150941건"(F34) → F34 = `top_peer_1 {"peer": "X1", "connections": 150941}`, X1 = `172.16.0.1`.
- `H`, `I*`, `X*`는 글자 경계로 찾는다(`HTTP`의 H는 가명이 아니다). 번호 매기는 순서는 상위 상대 → 대표 연결이다.
- 보고서 글은 LLM이 쓴 문장이다. HTML로 해석하지 말고 글자 그대로 보여 준다(이스케이프).

### `dashboard.send_decisions`: 전송 판단(세 의견)

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `job_id`, `incident_id` | | 사건 키 |
| `zeekad_would_send` | boolean | **실제로 Slack에 보내는지.** A단계라 정책 규칙이 정한다 |
| `zeekad_decided_by` | text | 누가 정했나. 지금은 항상 `policy` |
| `policy_id`, `policy_choice` | text | 정책 규칙 버전(`policy.v1`)과 결정(`send`·`hold`) |
| `policy_mandatory` | boolean | 필수 전송 조건(큐 5위 이내 또는 2개 이상 모델이 꼽음)에 걸렸나 |
| `policy_reasons` | jsonb | 걸린 조건 문장 배열, 예: `["queue_rank 3 <= 5", "flagging_models 3 >= 2"]` |
| `llm_choice` | text | LLM 보고서의 의견(`send`·`hold`·`analyst_review`·`need_more_evidence`). 템플릿이면 null |
| `decision_model` | text | 판단 모델 이름(`gemini-decision-1`) |
| `decision_model_choice` | text | 판단 모델 의견. 호출 실패면 null |
| `decision_model_confidence` | double | 고른 선택지의 확률. **정확도가 아니다**(모델이 얼마나 한쪽으로 기울었는지) |
| `decision_model_probabilities` | jsonb | 선택지별 확률, 예: `{"send": 0.69, "hold": 0.07, ...}` |
| `decision_model_error` | text | 호출 오류 종류 |
| `zeekad_source_run`, `created_at` | | 실행, 시각 |

화면 권장: `zeekad_would_send`를 크게, 세 의견은 작게 나란히 둔다. 의견이 갈리면(예: 정책 send, 판단 모델 hold) 표시한다.

### `dashboard.slack_deliveries`: Slack 전송 기록

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `job_id`, `incident_id` | | 사건 키 |
| `zeekad_message_kind` | text | `incident`(사건 알림) 또는 `status`(상태가 바뀌었다는 후속 알림) |
| `zeekad_message_version` | text | 사건 알림이면 보고서 버전, 상태 알림이면 `status:investigating`·`status:closed` |
| `zeekad_delivery_mode` | text | `dry_run`(보내지 않고 기록만) 또는 `live` |
| `zeekad_delivery_status` | text | `recorded`(dry_run 기록), `delivered`, `failed` |
| `slack_payload` | jsonb | Slack Block Kit 본문 `{channel, text, blocks}`. 사건 자산의 실제 IP가 들어 있다 |
| `slack_ts`, `delivered_at`, `error` | | 실제 전송 때만 채워진다 |
| `created_at` | timestamptz | 기록 시각 |
| `zeekad_thread_parent` | text | 같은 자산 알림 묶음(DD-010 결정 5)의 머리 사건 `incident_id`. 이 알림은 그 사건 알림의 Slack 스레드 답글이다. 머리 알림 자신이면 null(머리 사건의 뒤 알림은 자기 자신). 2026-11-19 추가(migration 016) |
| `zeekad_reply_broadcast` | boolean | 답글을 채널에도 띄웠는가(30분 재알림). 2026-11-19 추가 |

지금은 Slack 토큰이 없어 모두 `dry_run`·`recorded`다. 2026-11-19부터 에이전트 알림은 같은 자산·역할의 미해결 알림 묶음(관측 시각 60분 안)이 있으면 스레드 답글로 기록된다. 화면에서 Slack처럼 묶어 보여 주려면 `zeekad_thread_parent`로 묶는다.

스레드 두 열을 읽는 법(2026-11-23 보완, Q72)

| 행 | `zeekad_thread_parent` | `zeekad_reply_broadcast` | 뜻 |
| --- | --- | --- | --- |
| `created_at`이 `2026-11-19T06:20:00Z` 앞 | null | false | **스레드 정보 없음.** 스레드 규칙을 넣기 전의 기록이다(migration 016 적용 `2026-11-19T06:19:54Z`). 머리 알림이라는 뜻이 아니다. 답글인지 채널 알림인지 그리지 않는다 |
| 그 뒤 | null | false | 채널에 새로 올린 머리 알림 |
| 그 뒤 | 자기 `incident_id` | false | 머리 사건의 뒤 알림(LLM 보고서 추가, 상태 변경). 자기 첫 알림의 스레드 답글이고 채널에 다시 띄우지 않는다 |
| 그 뒤 | 다른 사건의 `incident_id` | false | 같은 자산 묶음의 답글. 그 사건 첫 알림의 스레드에 붙는다 |
| 그 뒤 | 다른 사건의 `incident_id` | true | 묶음 답글이면서 채널에도 띄운 재알림(30분) |

- 기준 앞의 행은 126행이다(CIC·합성 캡처, `lab-20261201`·`lab-20261118`·`lab-20261119`). 다시 계산해 채우지 않는다. 그때 규칙의 기록이기 때문이다.
- dry-run이어도 두 열은 채운다. 실제 전송 여부와 상관없다.
- 묶음은 캡처(UTC 날짜)를 넘는다. `lab-20261123` 알림의 머리 사건은 모두 `lab-20261122`에 있다. 캡처 하나만 뽑으면 부모 행이 빠질 수 있다.
- 같은 사건의 뒤 알림은 언제나 채널에 다시 띄우지 않는 답글이다. 한 사건이 채널에 두 번 뜨지 않는다. 재알림(`zeekad_reply_broadcast = true`)은 묶음에 새로 붙는 사건의 첫 알림에만 붙는다.

### `dashboard.slack_summaries`: Slack 일일 요약

`job_id`, `capture_id`, `zeekad_message_version`(`daily-summary.v1`), `zeekad_delivery_mode`, `zeekad_delivery_status`, `slack_payload`, `slack_ts`, `delivered_at`, `created_at`. 채점 작업(캡처 하루)마다 하나다. 보내지 않은 사건 수와 ID도 들어 있다(DD-001).

### `dashboard.incident_status`: 사건 상태

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `job_id`, `incident_id` | | 사건 키. 완료된 작업의 **모든** 사건이 나온다. 상태는 `incident_id`에 붙어 있어 같은 사건이면 작업이 달라도 같다(v2.1) |
| `zeekad_status` | text | `open`(열림), `investigating`(확인 중), `closed`(종료) |
| `zeekad_resolution` | text | 종료 결론: `true_positive`(실제 공격), `false_positive`(오탐), `benign`(이상하지만 정상 업무). 종료가 아니면 null |
| `updated_at`, `updated_by` | | 마지막 변경. 한 번도 안 바뀐 사건은 null |

### `dashboard.incident_status_history`: 상태 변경 이력

`job_id`, `incident_id`, `from_status`, `to_status`, `zeekad_resolution`, `actor`(누가), `reason`(왜), `changed_at`. 추가만 되는 기록이다. 고치거나 지울 수 없다.

### `dashboard.analyst_review_queue`: 분석가 검토 요청

| 열 | 뜻 |
| --- | --- |
| `job_id`, `incident_id`, `queue_rank`, `host_ip`, `zeekad_role` | 사건 |
| `zeekad_review_reason` | 멈춘 이유, 예: `decision_model=analyst_review` |
| `requested_at` | 에이전트 흐름이 멈춘 시각 |
| `zeekad_review_action` | `confirm`(조사 진행) 또는 `dismiss`(오탐으로 종료). 아직 결정 전이면 null |
| `analyst`, `decided_at` | 결정한 사람과 시각 |
| `zeekad_review_resumed_at` | 파이프라인이 멈춘 흐름을 재개해 끝낸 시각. 결정했지만 아직이면 null(보통 30초 안에 채워진다). 2026-11-19 추가(migration 014) |
| `zeekad_review_resume_failed` | 재개가 실패했으면 true. 파이프라인 운영자가 명령줄로 다시 재개한다. 2026-11-19 추가 |

판단 모델이 `analyst_review`를 고른 사건만 들어온다. "결정 전" 목록은 `zeekad_review_action IS NULL`이다.

## 쓰기: 사건 상태 변경

| 항목 | 값 |
| --- | --- |
| 계정 | `dashboard_rw`. 비밀번호는 `deploy/.env`의 `DASHBOARD_RW_PASSWORD`(환경 변수로 받는다) |
| 권한 | 함수 `dashboard.transition_incident` 실행만. 표에 직접 INSERT·UPDATE할 수 없다 |

```sql
SELECT dashboard.transition_incident(
    p_job        => 4,
    p_incident   => 'cic17-fri|192.168.10.14|originator|1499428800',
    p_to         => 'closed',          -- 'investigating' 또는 'closed'
    p_actor      => 'analyst01',       -- 로그인한 사용자
    p_reason     => '도메인 컨트롤러 정상 업무',
    p_resolution => 'false_positive'   -- closed일 때만, 셋 중 하나
);  -- 반환: 바뀐 상태
```

- 한 칸씩만 앞으로 간다: `open → investigating → closed`. 되돌리기와 건너뛰기는 함수가 거부한다(SQLSTATE `22023`). 사건이 없으면 `02000`이다. 종결한 사건을 다시 여는 것은 이 함수가 아니라 아래 "쓰기: 종결한 사건 다시 열기"의 함수로 한다.
- `actor`와 `reason`은 비울 수 없다. 오류 메시지는 한국어 문장이라 그대로 보여 줘도 되지만 zeek_AD의 용어("사건", "화면")로 쓰여 있다. 화면 용어(예: "인시던트")와 맞추려면 문장 대신 SQLSTATE(`02000` 대상 없음, `22023` 값·상태 오류)로 화면 문구를 정한다. 문장은 바뀔 수 있고 SQLSTATE는 바뀌지 않는다(2026-11-27, 아래 재개·검토 결정 함수도 같다).
- 같은 사건을 두 사람이 동시에 바꾸면 하나만 성공한다. 다른 하나는 "허용되지 않는 상태 변경"으로 거부된다(행 잠금).
- 화면 권장: 버튼은 지금 상태에서 갈 수 있는 다음 상태만 보여 준다. 종료 버튼은 결론 세 가지 중 하나를 고르게 한다.

## 쓰기: 종결한 사건 다시 열기(2026-11-26 추가, migration 018, [DD-022](design-decisions/DD-022-incident-reopen.md))

| 항목 | 값 |
| --- | --- |
| 계정 | `dashboard_rw`(상태 변경과 같은 계정). 파이프라인 계정에는 실행 권한이 없다 |
| 권한 | 함수 `dashboard.reopen_incident` 실행 |

```sql
SELECT dashboard.reopen_incident(
    p_job      => 83,
    p_incident => 'lab-20261122|10.10.0.50|originator|1795362000',
    p_actor    => 'analyst01',       -- 로그인한 사용자
    p_reason   => '같은 출발지의 스캔이 다시 관측됨',
    p_expected_resolution => 'false_positive'   -- 선택(권장). 화면이 보고 있던 결론
);  -- 반환: 'investigating'
```

- 지금 상태가 `closed`일 때만 성공한다. 사건은 `investigating`이 되고 결론(`zeekad_resolution`)은 null이 된다. 다시 종결할 때는 `dashboard.transition_incident`로 결론을 새로 고른다.
- 거부(SQLSTATE): 상태가 `closed`가 아니면 `22023`("종료한 사건만 다시 열 수 있다. 지금 상태: …"), `p_actor`나 `p_reason`이 비었으면 `22023`, `p_job`에 그 사건이 없으면 `02000`. 오류 메시지는 한국어 문장이다.
- 이력(`dashboard.incident_status_history`)에 `from_status = 'closed'`, `to_status = 'investigating'`, `resolution = null` 행이 추가된다. 되돌린 결론은 앞선 종결 행에 남아 있다.
- 재개를 별도 함수로 둔 이유: `transition_incident(p_to => 'investigating')`는 "처음 조사 시작"에도 쓰인다. 같은 함수가 재개까지 받으면, 다른 사람이 종결한 사건을 오래된 화면의 "분석 시작"이 다시 열어 결론을 지운다. 그 호출은 지금처럼 `22023`으로 거부된다.
- `p_expected_resolution`(선택, 권장): 화면이 보고 있던 결론(`zeekad_resolution`)을 보내면 지금 결론과 같을 때만 다시 연다. 다르면 `22023`으로 거부한다. 그 사이 다른 사람이 다시 열어 새 결론으로 종결한 사건을 오래된 화면이 지우지 못하게 하는 장치다. 보내지 않으면(null) 상태가 `closed`인지만 본다.
- 같은 사건을 두 사람이 동시에 다시 열면 하나만 성공한다. 다른 하나는 "지금 상태: investigating"으로 거부된다(행 잠금). 기본 격리 수준(READ COMMITTED) 기준이다. REPEATABLE READ 이상으로 부르면 `40001`(직렬화 실패)이 날 수 있고, `transition_incident`도 같다.
- 재개한 사건은 결론이 없으므로 분석가 결론 집계(`dashboard.feedback_summary`)의 "결론 난 사건"에서 빠진다.
- 화면 권장: "다시 열기" 버튼은 종결 상태의 사건에만 보여 주고 사유를 받는다. 누가 다시 열 수 있는지는 대시보드의 권한으로 정한다.
- 공개 데모 DB(스냅샷 복원본)에는 `db/migrations/018_incident_reopen.sql` 하나를 실행하면 된다. 표와 뷰를 바꾸지 않고 함수 하나와 그 소유자·권한만 정하며, 다시 실행해도 결과가 같다. 선행 조건은 migration 012까지 적용된 DB와 `zeekad_owner`·`dashboard_rw` 역할이다. 파일이 함수 소유자를 `zeekad_owner`로 맞추므로 슈퍼유저로 실행해도 된다.
- 반영 순서: 파이프라인 이미지 → migration 018 → 대시보드의 "다시 열기" 버튼. 이유는 DD-022 "배포 순서".

## v2.1 보완(2026-11-17): 같은 캡처에 채점 작업이 여러 개일 때(Q54)

- 정의: [012_incident_identity.sql](../db/migrations/012_incident_identity.sql). 기존 뷰의 열 이름과 뜻은 그대로다. 뷰 하나를 추가했다.
- 배경: 실습망 캡처(`lab-YYYYMMDD`, DD-012·015)는 5분 파일이 올 때마다 그날을 다시 계산해 **같은 캡처에 작업이 여러 개** 생긴다. 같은 사건이 작업마다 다시 나온다. CIC·합성 캡처는 지금 캡처마다 작업이 하나다(모델 묶음을 바꾸면 늘어난다).
- **사건의 정체는 `incident_id`다**(`캡처|자산|역할|시작 epoch`). 다시 계산해도 같은 사건이면 같다.
  - 상태: `incident_id` 하나에 붙는다. 어느 작업에서 바꿔도 모든 작업의 `dashboard.incident_status`에 같은 상태가 보인다.
  - 보고서·전송 판단·분석가 검토: 그 사건을 처리한 작업에 있다. 보통 처음 나온 작업이지만, 뒤 파일에서 창이 이어 붙어 사건이 늘어나면 그 작업에서 다시 만든다(2026-11-18 보완, [DD-016](design-decisions/DD-016-lab-capture-coverage-and-report-refresh.md) 결정 3). 최신 보고서는 `zeekad_report_job_id`가 가리킨다.
  - Slack 기록: 처음 알린 작업에만 있다. 다시 만든 보고서는 Slack에 다시 보내지 않으므로(DD-016 결정 4) `zeekad_report_job_id`의 작업에는 Slack 기록이 없을 수 있다. **사건의 Slack 기록은 `incident_id`로 찾는다.**

### `dashboard.latest_incident_queue`: 캡처별 최신 큐(화면의 "조사 큐"는 이 뷰를 쓴다)

캡처마다 가장 최근 성공 작업(가장 큰 `job_id`)의 사건만 나온다. `incident_queue`의 열 전부에 아래 열이 붙는다.

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `zeekad_report_job_id` | bigint | 이 사건의 최신 보고서·판단·검토가 있는 작업. 없으면 null. **`incident_reports`·`send_decisions`·`analyst_review_queue`와 조인할 때는 `job_id` 대신 이 값을 쓴다**. `slack_deliveries`는 `incident_id`로 찾는다(DD-016) |
| `zeekad_report_kind` | text | `llm`·`template`, 보고서가 없으면 null |
| `zeekad_would_send` | boolean | 실제 전송 여부, 판단이 없으면 null |
| `zeekad_status`, `zeekad_resolution`, `status_updated_at` | | 사건 ID 기준 상태 |
| `zeekad_review_action`, `zeekad_review_pending` | | 분석가 검토 결정, 결정 전이면 pending이 true |

- 성능(2026-11-27, migration 019): 이 뷰는 사건 행마다 그 사건의 가장 최근 보고서를 찾는다. 이를 위한 인덱스 `zeekad.agent_report_incident_job_idx`(`incident_id`, `job_id DESC`)가 있다. 뷰와 결과는 그대로다. 공개용 DB 사본에 인덱스를 따로 넣는다면 같은 이름에 `IF NOT EXISTS`를 쓰면 019가 적용된 스냅샷에서 겹치지 않는다(Q87).
- `queue_rank`의 동점: 점수가 같은 사건끼리의 순서는 그 작업 입력의 해시로 정한다. 실습망 캡처는 파일이 늘 때마다 해시가 바뀌어 동점 사건끼리 자리가 작업마다 바뀔 수 있다(사건 ID와 점수는 그대로, Q86). 순위 숫자를 사건의 고유 값으로 쓰지 않는다. 화면에서 "N위"를 고정된 사실처럼 문서·예시에 박지 않는다.
- 결합 v2(2026-11-19, [DD-018](design-decisions/DD-018-fusion-merge-overlaps.md))부터 사건 창(`incident_window`)은 처음 뽑은 모델의 창이 아니라 겹쳐 꼽은 모든 모델 창의 합이다. 표·뷰 구조는 같다. 어느 결합 버전으로 만든 작업인지는 작업의 `bundle_id`로 안다.
- 사건 상세 화면의 모델 점수(`incident_model_scores`)와 근거 API는 큐에 나온 `job_id`(최신 작업)를 쓴다. 근거는 최신 작업 기준이라 사건이 길어졌으면 보고서보다 연결 수가 많을 수 있다.
- 상태 변경 함수(`dashboard.transition_incident`)의 호출 모양은 그대로다. `p_job`에는 화면이 보고 있는 작업(최신 큐의 `job_id`)을 넣는다. 그 작업에 그 사건이 없으면 `02000`으로 거부된다.
- 확인(2026-11-17): `lab-20261201` 최신 작업 23의 사건 6건 중 4건은 보고서 작업 21, 2건은 23. 작업 23에서 `.80`을 확인 중으로 바꾸자 작업 21·22·23 모두 확인 중으로 보였고, 이전 작업 21에서 같은 변경을 다시 보내면 "허용되지 않는 상태 변경: investigating → investigating"으로 거부됐다.

## 쓰기: 분석가 검토 결정(2026-11-19 추가, [DD-019](design-decisions/DD-019-review-decision-path.md))

| 항목 | 값 |
| --- | --- |
| 계정 | `dashboard_rw`(상태 변경과 같은 계정) |
| 권한 | 함수 `dashboard.decide_review` 실행만. 표에 직접 쓸 수 없다 |

```sql
SELECT dashboard.decide_review(
    p_job      => 41,                  -- 검토 요청의 job_id(analyst_review_queue의 job_id)
    p_incident => 'lab-20261119|10.10.0.102|originator|1795062900',
    p_action   => 'dismiss',           -- 'confirm'(조사 진행) 또는 'dismiss'(오탐으로 종료)
    p_analyst  => 'analyst01',         -- 로그인한 사용자
    p_note     => '정상 업무'            -- 선택
);  -- 반환: 결정 값
```

- 함수는 결정을 기록할 뿐이다. 멈춘 에이전트 흐름은 파이프라인이 찾아 재개한다(감시 주기 30초). 재개되면 `confirm`은 사건 상태를 `investigating`으로, `dismiss`는 `investigating → closed(false_positive)`로 바꾸고 상태 이력의 `actor`·`reason`에 결정한 사람과 메모가 들어간다. 결과는 `zeekad_review_resumed_at`과 상태 뷰로 확인한다.
- 거부(SQLSTATE): 결정 값이 둘 중 하나가 아니거나 `p_analyst`가 비었으면 `22023`, 검토 요청이 없으면 `02000`, 이미 결정한 요청이면 `22023`. 결정은 한 번뿐이다.
- 화면 권장: 결정 버튼은 `zeekad_review_action IS NULL`인 요청에만 보여 준다. 같은 사건의 요청이 여러 작업에 있으면 `zeekad_report_job_id`의 것만 보여 준다.
- 상태를 대시보드에서 먼저 바꿔도 된다. 흐름이 재개될 때 이미 지난 상태는 건너뛴다.
- 결정한 뒤에 분석가가 그 사건을 종결했다가 다시 열었으면(`dashboard.reopen_incident`), 파이프라인은 앞선 `dismiss` 결정으로 그 사건을 다시 닫지 않는다(2026-11-26, DD-022). 이때 검토 뷰에는 `zeekad_review_action = 'dismiss'`와 `zeekad_review_resumed_at`이 있는데 사건 상태는 `investigating`이다. 재개 실패가 아니다(`zeekad_review_resume_failed`는 false다). 결정이 다시 연 것보다 나중이면 지금처럼 닫는다.

## 분석가 결론 집계(2026-11-19 추가, migration 017, Q61)

### `dashboard.feedback_summary`: 캡처 × 묶음 버전 × 처음 뽑은 모델별 결론 집계

캡처의 최신 큐(`latest_incident_queue`) 사건을 센다. `zeekad_picked_by = 'all'`은 그 캡처·묶음 전체 행이다.

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `capture_id`, `bundle_id`, `zeekad_picked_by` | text | 집계 단위 |
| `incidents`, `alerted` | bigint | 큐의 사건 수, 그중 Slack으로 알린 사건 수(`incident_id` 기준) |
| `resolved`, `true_positive`, `false_positive`, `benign` | bigint | 종료 결론이 난 사건 수와 결론별 수 |
| `zeekad_precision` | numeric | 실제 공격 ÷ 결론 난 사건. 결론이 없으면 null. benign은 공격이 아닌 쪽에 센다 |
| `zeekad_alert_precision` | numeric | 알린 사건 중 결론 난 것에서의 실제 공격 비율 |
| `zeekad_alert_resolved_rate` | numeric | 알린 사건 중 결론 난 비율. 낮으면 정밀도를 믿기 어렵다 |

- 라벨 없는 운영에서 쌓이는 유일한 라벨(분석가 종료 결론)로 알림 품질을 본다. 놓친 공격(재현율)은 알 수 없다.
- 화면 제안: 정밀도 옆에 결론 수(`resolved`)와 결론 비율을 같이 보여 준다(예: "정밀도 0.60, 결론 5/18").
- `alerted`와 `slack_deliveries`의 사건 알림은 같은 범위다(2026-11-21 확인, Q67). `slack_deliveries`는 성공한 작업만 걸러 내고 `alerted`는 거르지 않지만, Slack 기록은 성공한 작업의 사건에만 생기므로 결과가 같다.
  - Slack 기록은 사건 행을 외래 키로 가리킨다(`(job_id, incident_id)`).
  - 사건 행은 작업을 `succeeded`로 바꾸는 같은 트랜잭션에서만 쓰인다. 끝나지 않은 작업의 사건은 이어받을 때 지워진다.
  - `succeeded`가 된 작업은 다시 `running`·`failed`로 바뀌지 않는다.
  - 에이전트는 성공한 작업의 사건만 처리한다.
  - 배포 VM DB(2026-11-21): Slack 기록 126행 모두 성공한 작업이다. 성공하지 않은 작업은 0개다.
  - 따라서 두 값이 다르면 zeek_AD 결함이다. zeek_AD에 알린다.
  - 둘 다 Slack 전송 상태(`recorded`·`delivered`·`failed`)는 가리지 않는다. 실제 전송(`live`)을 켜면 "전송 실패"도 알린 것으로 센다. 그때 정의를 다시 정한다.

## 모델 표시 이름(2026-11-21 추가, Q63)

탐지 모델 식별자는 DB 값 그대로 둔다(`zeekad_picked_by`, `zeekad_also_flagged_by`, `zeekad_model`, `model_bundles.thresholds`의 키, `feedback_summary.zeekad_picked_by`). 화면에는 아래 표시 이름을 쓴다. 각 모델이 무엇을 보는지는 이 저장소가 기준이다. DB·뷰는 바꾸지 않았다.

| 식별자 | 표시 이름 | 모델 종류 | 툴팁 |
| --- | --- | --- | --- |
| `tail_rarity_v2` | 기준선 이탈 | 통계 기준선 | 5분 구간의 통신 특징 42개(연결 수, 목적지 포트 수, 연결 실패 비율, 프로토콜 로그 등) 중 정상 기간에 거의 없던 값이 있는 정도. 가장 드문 특징 하나가 점수다. 정찰·스캔, 인증 실패 반복에 강하다. |
| `transformer_v2` | 행위 패턴 이탈 | Transformer | 이 자산의 직전 1시간(5분 구간 12개)으로 다음 5분을 예측하고, 실제와 다른 정도. 다른 자산이 아니라 자기 평소 흐름과 비교한다. 이력이 없는 첫 구간에서는 높게 나올 수 있다. |
| `tgn_recon` | 통신 관계 이상 | TGN(시간 그래프 신경망) | 호스트 사이의 연결을 시간 그래프로 학습해, 예상하기 어려운 연결이 나온 정도(구간 안에서 가장 예상 밖인 연결 하나 기준). beacon처럼 양은 적어도 상대가 특이한 통신을 올린다. 이상 호스트와 통신한 정상 호스트도 함께 올라갈 수 있다. |

- 표에는 표시 이름만 쓴다. 상세 화면과 툴팁에는 모델 종류와 식별자를 함께 둔다(예: "Transformer · `transformer_v2`").
- 표시 이름에 버전을 넣지 않는다. 같은 식별자는 같은 모델이다. 모델이 바뀌면 식별자가 바뀌고, 그때 이 표에 행을 더한다.
- 근거: [configs/models/transformer.v2.json](../configs/models/transformer.v2.json)(직전 12칸, 42개 특징 예측 오차), [configs/models/tgn.v1.json](../configs/models/tgn.v1.json)(연결 이벤트 복원 오차, 창 안 최댓값), [단계 3 진행 기록](stage-3-progress.md)(꼬리 희귀도: 특징별 양쪽 꼬리, 최댓값), 강약은 README 결과 해석.

## 수집 구간(캡처) 표시 이름(2026-11-21 추가, Q65)

`capture_id`는 DB 값 그대로 둔다(열람 허용 패턴 `cic17-*`·`syn1-*`도 그대로). 화면에는 아래 규칙으로 만든 이름을 쓰고, 원래 ID는 툴팁에 둔다. 요일은 `mon`·`tue`·`wed`·`thu`·`fri` → 월·화·수·목·금.

| 캡처 ID 형식 | 표시 이름 | 툴팁 |
| --- | --- | --- |
| `cic17-<요일>` | CIC-IDS2017 <요일>요일 | 공개 데이터셋 CIC-IDS2017의 원본 트래픽(평가용). 월요일 정상만 학습에 썼다. |
| `syn1-<요일>` | CIC <요일>요일 + 합성 패턴 | CIC <요일>요일 Zeek 로그 사본에 합성 패턴 5종(beacon, 느린 유출, DNS 터널, 측면 이동, 느린 정찰)을 하나씩 코드로 끼워 넣었다. 네트워크로 보낸 트래픽이 아니다([DD-008](design-decisions/DD-008-synthetic-apt-injection.md)). |
| `lab-YYYYMMDD` | 실습망 YYYY-MM-DD | 배포 VM이 격리 실습망에서 실제로 수집한 트래픽(날짜는 UTC). 하루가 처리 단위다. |

실습망 캡처별 표시(배포 VM DB 기준, 2026-11-23, 2026-11-26 갱신)

| 캡처 | 덧붙일 표시 | 내용 |
| --- | --- | --- |
| `lab-20261126` | 오탐 규칙 뒤 재실행 | 브로드캐스트뿐인 창을 조사 큐에서 빼는 규칙([DD-021](design-decisions/DD-021-queue-eligibility-non-host-only.md))을 배포한 뒤의 실습망. 02:15\~04:45 UTC는 유휴(브로드캐스트만, 사건 0건). 04:50\~05:00 연결 확인, 05:05\~05:20 타깃 정상 배경, 05:25\~05:40 비커닝, 05:45\~06:00 분할 유출(정답 `lab-ep-012`·`013`). 연결 확인과 정상 배경 창도 사건이 된다(새 자산의 한계). [실습망 공격 탐지 결과](lab-attack-detection.md) "규칙 전과 뒤" |
| `lab-20261124`, `lab-20261125` | 유휴(규칙 전) | 공격이 없는 날. 타깃 VM의 NetBIOS 브로드캐스트 한 건이 5분마다 사건이 됐다(규칙 전, 사건 118건·35건). **시연 화면에서는 숨기길 권한다**(규칙 전의 오탐 사례는 `lab-20261122`의 사건으로 충분하다) |
| `lab-20261122` | Kali 공격 6종 + 타깃 VM | 세그먼트 센서 확장(DD-020) 뒤의 공격 시험: 느린 스캔, 비커닝, 분할 유출, SMB 공유 탐색, SSH 무차별 대입, DNS 터널(빠른 스캔은 `lab-20261119`에 있다. 정답은 `configs/ground-truth/lab-attacks.v1.json`, [단계 7 진행 기록](stage-7-progress.md) 열두째 작업). 호스트: 10.10.0.50 Kali(공격자), 10.10.0.60 Kali의 별칭(정상 배경용 서버), 10.10.0.20 타깃 VM, 10.10.0.21\~23 타깃의 IP 별칭(공유 탐색용). 스레드 묶음이 처음 기록된 캡처다 |
| `lab-20261123` | 시험(위 캡처의 뒤 시간) | `lab-20261122` 시험 뒤 UTC 날짜가 넘어간 구간. 5분에 패킷 몇 개의 유휴 트래픽이고 공격 실행 기록은 없다. 알림은 모두 `lab-20261122` 묶음의 답글이다 |
| `lab-20261119` | Kali 공격 + 정상 배경 | Kali 공격만(실행 1), 정상 배경 35분(월요일 재생 + 합성 정상 클라이언트) 사이에 공격(실행 2). 시험 호스트 구분은 [2026-11-19 전달 글](dashboard-handoff-2026-11-19.md) 5절 |
| `lab-20261118` | 시험 | 배포 VM 첫 실행. Kali nmap 첫 시험, ping·파일 회전 시험 |
| `lab-20261201` | 시험(가짜 패킷) | VM을 만들기 전 이 PC에서 시험용 생성기로 만든 패킷(날짜도 가짜). DB를 옮길 때 함께 넘어갔다. **시연 화면에서는 숨긴다**(DB에서 지우지 않는다) |

- 위 표에 없는 새 `lab-*` 캡처는 덧붙일 표시 없이 "실습망 YYYY-MM-DD"로 보인다. 시험 캡처가 새로 생기면 zeek_AD가 표에 행을 더한다.

## 알려진 빈칸(v2에서 다루지 않음)

1. ~~대시보드에서 분석가 검토를 끝내는 방법이 없다.~~ 2026-11-19 해결: 위 "쓰기: 분석가 검토 결정"(DD-019). Q50의 원안(근거 API가 흐름을 재개)은 쓰지 않았다. API는 읽기 전용 그대로다.
