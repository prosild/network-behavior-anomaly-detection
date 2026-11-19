## 1. 데이터는 어디서, 어떤 형태로 들어오나

**대시보드는 Zeek 로그를 직접 읽지 않습니다. PostgreSQL의 읽기 전용 뷰만 읽습니다.** Kafka나 실시간 스트림은 없습니다.

데이터는 Python 프로젝트(zeek_AD)가 미리 처리해 PostgreSQL에 넣어 둡니다.
- 처리 순서: Zeek 로그 → Spark 특징 → 이상탐지 모델 3개(TGN, 꼬리 희귀도, Transformer) → 순위를 번갈아 합친 하루 조사 큐 → 사건별 근거 JSON
- 자료: CIC-IDS2017(2017년 7월 캡처를 다시 재생한 자료) 화~금 4일과, 같은 날에 합성 공격을 넣은 4일, 모두 8개 캡처입니다.
- 처리 방식: 캡처 하나를 채점 작업 하나로 배치 처리합니다. 작업마다 사건이 약 250~290건 나옵니다.
- 실습망 캡처(`lab-YYYYMMDD`): Kali VM 공격을 실제로 캡처한 날입니다. 5분 파일이 들어올 때마다 그날을 다시 계산하므로 **같은 캡처에 채점 작업이 여러 개** 생깁니다(2장 v2.1).

### 접속

| 항목 | 값 |
| --- | --- |
| 서버 | PostgreSQL 17, `127.0.0.1:55432`. 같은 PC 안에서만 열려 있습니다 |
| DB | `zeekad` |
| 계정 | `dashboard_ro`. 비밀번호는 환경 변수로 받습니다. 코드와 Git에 넣지 않습니다 |
| 권한 | `dashboard` 스키마의 뷰 SELECT만 됩니다. 원래 표와 쓰기는 막혀 있습니다 |
| 쓰기 계정 | `dashboard_rw`. 사건 상태 변경 함수 하나만 실행할 수 있습니다(2장 끝). 읽기와 쓰기 연결 설정을 따로 둡니다 |
| 대시보드 자체 DB | 같은 서버의 `zeekad_dashboard`. 소유 계정 `dashboard_app`(비밀번호 환경 변수 `DASHBOARD_APP_PASSWORD`). 표는 Flyway로 직접 만듭니다. 이 계정은 `zeekad`·`mlflow` DB에 접속할 수 없고, 다른 계정은 `zeekad_dashboard`에 접속할 수 없습니다 |

- **배포(DD-015)**: 이 PC의 VMware에 배포 VM 하나를 두고, zeek_AD와 대시보드를 같은 Docker Compose로 올립니다. 공격은 다른 VMware VM(Kali)에서 격리된 실습망으로 보냅니다(NAS 배포 계획은 취소).
  - 개발 중에는 지금처럼 `127.0.0.1:55432`에 접속합니다. 배포 때는 같은 Compose 네트워크 안에서 서비스 이름(예: `postgres:5432`)으로 접속합니다. 주소·포트·계정·비밀번호는 모두 환경 변수로 받아 주세요.
  - 대시보드와 앞단 Nginx·ModSecurity가 Compose 서비스로 들어갈 수 있게 Dockerfile(또는 이미지 빌드 방법)과 필요한 환경 변수 목록을 준비해 주세요. 사용자는 Windows 브라우저에서 배포 VM 주소로 접속합니다.

### 데이터 계약 v1 뷰(고정)
- 계약을 바꿀 때는 v2를 만듭니다. v2에서는 열을 추가만 하고, 기존 열을 지우거나 뜻을 바꾸지 않습니다.
- 이름 규칙: ECS 이름을 밑줄로 씁니다. 예를 들어 `host_ip`는 `host.ip`, `event_start`는 `event.start`입니다. 이 프로젝트에만 있는 값에는 `zeekad_` 접두사가 붙습니다.
- 시각은 모두 UTC `timestamptz`입니다.

**`dashboard.incident_queue`: 조사 큐**

| 열 | 뜻 |
| --- | --- |
| `job_id`, `capture_id`, `bundle_id` | 채점 작업, 캡처(예: `cic17-wed`, `syn1-tue`), 모델 묶음(예: `zeekad-fusion/1`) |
| `queue_rank` | 그날의 조사 순서. 1부터 시작합니다 |
| `incident_id` | 사건 ID. 형식은 `capture\|asset\|role\|first_start(epoch)` |
| `host_ip`, `zeekad_role` | 사건의 자산, 역할(`originator` 또는 `responder`) |
| `event_start`, `event_end` | 사건 범위. 5분 창 단위이고 최대 30분입니다 |
| `zeekad_picked_by`, `zeekad_also_flagged_by` | 이 사건을 꼽은 모델, 같은 사건을 겹쳐 꼽은 다른 모델(배열) |
| `connection_count` | 연결 수 |
| `host_name` | Zeek에서 관측한 이름(배열). 없으면 null |

**나머지 뷰**

| 뷰 | 열 | 주의할 점 |
| --- | --- | --- |
| `dashboard.incident_model_scores` | `job_id`, `incident_id`, `zeekad_model`, `max_score`, `candidate_windows`, `windows` | **모델끼리 점수 척도가 달라 서로 비교하면 안 됩니다.** 같은 화면에 놓을 때는 "임계값 이상인 창 수 / 전체 창 수"로 보여 주세요 |
| `dashboard.asset_names` | 캡처·자산별 Kerberos·NTLM 관측 이름, 출처 로그, 관측 수, 처음·마지막 시각 | 사용자 이름(`kerberos_user`, `ntlm_user`)과 IP는 개인정보가 될 수 있습니다. 마스킹과 원문 열람 권한은 대시보드 쪽에서 정합니다 |
| `dashboard.scoring_jobs` | `job_id`, `capture_id`, `bundle_id`, `status`(running·succeeded·failed), `started_at`, `finished_at`, `error`, `incident_count` | |
| `dashboard.model_bundles` | `bundle_id`, `registry_name`, `registry_version`, `manifest_sha256`, `registered_at`, `thresholds`(jsonb, 모델 → 임계값) | |

### 사건 상세(근거)
- 근거 조회 API(Python FastAPI, 읽기 전용)가 있습니다. 주소는 `http://127.0.0.1:8000`입니다.

  | 경로 | 내용 |
  | --- | --- |
  | `GET /api/v1/jobs` | 작업 목록 |
  | `GET /api/v1/captures/{capture_id}/queue?limit=10` | 그 캡처의 최신 완료 작업 큐 |
  | `GET /api/v1/jobs/{job_id}/incidents/{rank}` | 모델별 점수·임계값, 자산 이름, 근거 JSON(`evidence.v1`) |

- `evidence.v1`에는 다음이 들어 있습니다.
  - 연결 수, 전송 계층·프로토콜별 수
  - 보낸·받은 바이트
  - 연결 상태별 수
  - 상위 상대 IP·포트
  - 프로토콜 로그 수치(dns, http, tls, ssh, ftp, smb, kerberos, dce_rpc, ntlm)
  - 대표 연결(최대 10개)
  - 관측 한계 문장
- 지금은 서비스 간 인증이 없습니다. 같은 PC 안에서만 열려 있기 때문입니다. 대시보드가 API를 호출하는 구조로 갈지, 같은 내용을 DB 뷰로 받을지 정해 주세요. 뷰가 필요하면 zeek_AD 쪽에서 추가합니다.

### 개발 데이터
- 실제 데이터가 이미 DB에 있습니다(사건 약 2,100건). 샘플 데이터를 생성할 필요는 없습니다.
- 다른 PC에서 개발한다면 위 뷰의 내용을 CSV나 JSON으로 내보내 줄 수 있습니다.

## 2. 단계 5 결과: 보고서, 알림 판단, 사건 상태(데이터 계약 v2, 고정)

1장의 v1 뷰는 그대로이고, v2에서 뷰가 추가만 됐습니다. 전체 열 정의는 zeek_AD의 `docs/data-contract-v2.md`에 있습니다. 여기서는 화면을 만들 때 필요한 것만 적습니다.

### v2.1: 조사 큐는 `dashboard.latest_incident_queue`로 그립니다
- 같은 캡처에 작업이 여러 개일 수 있습니다(실습망). 같은 사건이 작업마다 다시 나옵니다. **사건의 정체는 `incident_id`**(`캡처|자산|역할|시작 epoch`)입니다.
- `latest_incident_queue`는 캡처마다 최신 작업의 큐만 보여 주고, 사건마다 다음을 붙입니다.
  - `zeekad_report_job_id`: 보고서·판단·Slack·검토가 있는 작업. **`incident_reports`·`send_decisions`·`slack_deliveries`·`analyst_review_queue`와 조인할 때는 `(zeekad_report_job_id, incident_id)`를 씁니다.** null이면 "보고서 없음"입니다.
  - `zeekad_report_kind`, `zeekad_would_send`, `zeekad_status`, `zeekad_resolution`, `status_updated_at`, `zeekad_review_action`, `zeekad_review_pending`(검토 결정 전이면 true).
- 모델 점수(`incident_model_scores`)와 근거 API는 큐의 `job_id`(최신 작업)를 씁니다.
- 상태는 `incident_id`에 붙습니다. 어느 작업에서 바꿔도 같은 사건이면 같은 상태입니다. 다음 파일이 들어와 새 작업이 생겨도 상태가 유지됩니다.
- CIC·합성 캡처는 지금 작업이 하나라 `job_id`와 `zeekad_report_job_id`가 같습니다.

**보고서·판단·Slack 기록은 일부 사건에만 있습니다.** 지금은 캡처마다 조사 큐 상위 일부, 모두 60건입니다. 나머지 사건은 v1 뷰만 있으니 "보고서 없음"으로 보여 주세요. 사건 상태는 모든 사건에 있습니다.

### `dashboard.incident_reports`: 사건 보고서

| 열 | 뜻 |
| --- | --- |
| `zeekad_report_kind` | `llm` 또는 `template`. `template`이면 LLM 보고서가 검증에 실패해서 규칙으로 만든 보고서로 바꾼 것입니다 |
| `zeekad_report` | 보고서 본문(jsonb, 아래 구조) |
| `zeekad_verification_passed`, `zeekad_verification_reason`, `zeekad_verification_problems` | LLM 보고서 검증 결과. 실패하면 어느 문장의 어떤 숫자가 근거에 없었는지 나옵니다 |
| `llm_model_requested`, `llm_model_version` | 요청한 모델과 실제 응답한 모델. 다를 수 있으니 둘 다 보여 주세요 |
| `llm_seconds`, `llm_input_tokens`, `llm_output_tokens`, `llm_thinking_tokens`, `llm_error` | 호출 시간, 토큰, 오류 |
| `zeekad_attack_candidates` | ATT&CK 후보 `[{attack_id, name, tactics}]`. **가설이지 정답이 아닙니다** |
| `zeekad_facts` | 보고서가 인용하는 사실 목록 `[{id, name, value}]` |
| `zeekad_pseudonyms` | 가명표 `{"H": IP, "I1": IP, "X1": IP}`. 실제 IP가 들어 있습니다 |

`zeekad_report` 구조:
- `observation_summary`: 한두 문장 요약
- `claims`: `[{claim, fact_ids}]`. 관측 사실 문장과 근거 사실 번호
- `possible_explanations`: `[{explanation, fact_ids, attack_ids}]`. 가능한 해석. 템플릿 보고서에서는 빈 배열입니다
- `send_recommendation`: `{choice, reason, fact_ids}`. LLM의 전송 의견입니다. 실제 전송 여부가 아니고, 템플릿 보고서에는 이 키가 없습니다
- `limitations`, `follow_up`: 한계, 추가로 확인할 것(문장 배열)

**보고서 글을 화면에 보이는 방법**
- 글 속 `F23`은 `zeekad_facts`의 `id`입니다. 주장 옆에 근거 사실(이름과 값)을 펼쳐 볼 수 있게 해 주세요.
- 글 속 `H`, `I1`, `X1`은 가명입니다. LLM에 실제 IP를 보내지 않으려고 씁니다. `H`는 사건 자산, `I*`는 내부 상대, `X*`는 외부 상대입니다.
  - 화면에서는 `zeekad_pseudonyms`로 실제 주소를 함께 보여 줍니다. 예: "X1(172.16.0.1)".
  - 가명은 글자 경계로 찾아야 합니다. 예를 들어 `HTTP`의 H는 가명이 아닙니다.
  - IP 원문 열람 권한을 역할별로 나눌 거라면, 가명표 표시도 같은 권한을 따르게 해 주세요.
- 예: 주장 "외부 피어 X1과의 연결이 150941건"(F34) → F34 = `top_peer_1 {"peer": "X1", "connections": 150941}` → X1 = `172.16.0.1`.

### `dashboard.send_decisions`: Slack 알림 판단(세 의견)

| 열 | 뜻 |
| --- | --- |
| `zeekad_would_send` | **실제로 보내는지.** 지금은 정책 규칙이 정합니다(`zeekad_decided_by` = `policy`) |
| `policy_choice`, `policy_mandatory`, `policy_reasons` | 정책 규칙의 결정(`send`·`hold`), 필수 전송 조건(큐 5위 이내 또는 2개 이상 모델이 꼽음)에 걸렸는지, 걸린 조건 문장 |
| `llm_choice` | 일반 LLM 의견. 템플릿 보고서면 null |
| `decision_model_choice`, `decision_model_probabilities`, `decision_model_confidence`, `decision_model_error` | 판단 모델(`gemini-decision-1`)의 선택과 선택지별 확률(`send`, `hold`, `analyst_review`, `need_more_evidence`) |

- 화면에서는 최종 전송 여부를 크게 보여 주고, 세 의견을 나란히 둡니다. 의견이 갈리면 표시해 주세요.
- **`decision_model_confidence`는 정확도가 아닙니다.** 모델이 한 선택지로 얼마나 기울었는지일 뿐입니다. 화면에 "정확도"나 "신뢰도 %"라고 쓰지 말고 "선택 확률"로 써 주세요.

### `dashboard.slack_deliveries`, `dashboard.slack_summaries`: Slack 기록
- `slack_deliveries`의 `zeekad_message_kind`는 `incident`(사건 알림) 또는 `status`(상태 변경 후속 알림)입니다. `slack_payload`가 보낸(보낼) 메시지 본문(Slack Block Kit JSON)입니다.
- `slack_summaries`는 캡처 하루마다 일일 요약 하나입니다. 보내지 않은 사건 수도 들어 있습니다.
- 지금은 Slack 토큰이 없어서 모두 `zeekad_delivery_mode = dry_run`, `zeekad_delivery_status = recorded`입니다. 화면에 "기록만(dry-run)"으로 표시해 주세요.

### 사건 상태: `dashboard.incident_status`, `dashboard.incident_status_history`
- 상태 `zeekad_status`: `open`(열림) → `investigating`(확인 중) → `closed`(종료). 한 번도 안 바뀐 사건은 `open`입니다. 상태는 `incident_id`에 붙어 작업이 달라도 같습니다(v2.1).
- 종료 결론 `zeekad_resolution`: `true_positive`(실제 공격), `false_positive`(오탐), `benign`(이상하지만 정상 업무).
- 이력에는 `from_status`, `to_status`, `actor`, `reason`, `changed_at`이 있습니다. 추가만 되고 고칠 수 없습니다.

### 분석가 승인 대기: `dashboard.analyst_review_queue`
- 판단 모델이 "분석가 확인 필요"를 고른 사건입니다. 해당 사건의 에이전트 흐름(LangGraph)은 멈춰서 결정을 기다립니다.
- 열: `queue_rank`, `host_ip`, `zeekad_role`, `zeekad_review_reason`, `requested_at`, `zeekad_review_action`(`confirm`·`dismiss`, 결정 전이면 null), `analyst`, `decided_at`.
- **승인·거절 버튼은 아직 연결할 곳이 없습니다.** 멈춘 흐름은 Python 쪽에서만 재개할 수 있기 때문입니다. zeek_AD가 배포 작업 때 근거 API에 결정 경로를 추가하면 그때 연결합니다(경로는 그때 알려 드립니다). 지금은 목록 화면과 버튼 자리만 만들어 주세요.

### 쓰기: 사건 상태 변경
`dashboard_rw` 계정으로 함수 하나만 부릅니다. 표에 직접 쓰는 권한은 없습니다.

```sql
SELECT dashboard.transition_incident(
    p_job => #{jobId}, p_incident => #{incidentId},   -- jobId: 화면이 보고 있는 큐의 job_id
    p_to => #{toStatus},            -- 'investigating' 또는 'closed'
    p_actor => #{loginUser},        -- 로그인한 사용자. 화면 입력이 아니라 서버 세션에서 넣습니다
    p_reason => #{reason},          -- 비울 수 없습니다
    p_resolution => #{resolution}   -- closed일 때만. true_positive·false_positive·benign
);  -- 반환값: 바뀐 상태
```

- 함수가 규칙을 강제합니다. 한 칸씩만 앞으로 가고, 되돌리기와 건너뛰기는 거부합니다.
  - 규칙 위반은 SQLSTATE `22023`, 사건이 없으면 `02000`입니다. 오류 메시지는 한국어 문장이라 사용자에게 그대로 보여 줘도 됩니다.
- 두 사람이 같은 사건을 동시에 바꾸면 하나만 성공합니다. 실패한 쪽은 화면을 새로 읽게 해 주세요.
- 버튼은 지금 상태에서 갈 수 있는 다음 상태만 보여 줍니다. 종료할 때는 결론 세 가지 중 하나를 고르게 합니다.
- 역할 검사(분석가 이상만 변경 가능)와 감사 로그는 대시보드 쪽에서 합니다. DB 이력에는 `p_actor`로 넘긴 이름이 남습니다.
- 상태가 바뀌면 zeek_AD가 Slack 후속 알림을 보내지는 않습니다. 후속 알림은 에이전트 흐름이 상태를 바꿀 때만 남습니다.

### 아직 없는 것
- **알림 묶음**(같은 자산·역할의 미해결 알림을 60분 안에 하나로 묶기): 아직 구현하지 않았습니다. 화면에 넣지 마세요.

## 3. 꼭 있어야 할 화면·기능

1. **로그인과 권한**
   - 역할은 조회자, 분석가, 관리자입니다.
   - 모든 요청을 서버에서 검사합니다. 버튼을 숨기는 것만으로는 부족합니다.
   - 사건·자산마다 객체 수준 권한을 확인합니다(IDOR 방지).
2. **조사 큐**
   - 캡처(날짜) 선택, `queue_rank` 순 목록을 보입니다.
   - 필터: 꼽은 모델, 역할, 자산, 상태, 보고서 있음/없음, 실제 전송 여부.
   - 같은 사건을 여러 모델이 꼽았는지 표시합니다.
3. **사건 상세**
   - 근거 요약(연결 수, 상대, 포트, 프로토콜 로그 수치, 대표 연결)
   - 모델별 "후보 창 수 / 창 수"
   - 관측 이름(출처 포함)
   - 보고서(근거 사실 펼치기, 가명 → 실제 주소), ATT&CK 후보, 알림 판단(세 의견), Slack 기록, 상태와 이력, 상태 변경
4. **운영 상태**: 채점 작업 목록·상태·오류, 모델 묶음 버전과 임계값.
5. **분석가 승인 대기 목록.** 승인·거절 버튼은 근거 API 경로가 생기면 연결합니다(2장).

## 4. 지켜야 할 것

**하지 않을 것**
- 대시보드가 zeekad의 표에 직접 쓰지 않습니다. 쓰기는 `dashboard.transition_incident` 함수 하나뿐입니다.
- 대시보드가 LLM을 호출하지 않습니다.
- 차단이나 격리 같은 대응을 실행하지 않습니다. 최종 판단은 사람이 합니다.

**출력할 때**
- LLM 보고서 문장과 로그에서 온 값(호스트 이름, 사용자 이름)은 신뢰하지 않는 입력입니다. 그대로 렌더링하지 말고 출력 인코딩과 CSP를 적용해 주세요. 프롬프트 인젝션된 문장이 화면에서 실행되면 안 됩니다.

**대시보드 자체 데이터**
- 대시보드 사용자, 역할, 감사 로그는 zeekad DB가 아니라 대시보드 자체 DB `zeekad_dashboard`에 둡니다(접속 표 참고).
- 감사 로그는 수정하거나 삭제할 수 없게 저장합니다.

**기술 선호**
- Spring Boot와 MyBatis를 씁니다. 사용자는 MyBatis 경험이 있고 JPA는 써 본 적이 없습니다.
- MyBatis에서는 `#{}`만 쓰고 `${}`는 쓰지 않습니다.

**보안 요구**
- 비밀번호: Argon2id 또는 bcrypt로 저장합니다.
- 관리자 2단계 인증: TOTP.
- 로그인 시도 제한과 계정 잠금.
- 세션: 로그인할 때 세션 ID를 새로 발급하고, 유휴 만료와 절대 만료를 둡니다.
- CSRF 토큰, 쿠키는 `Secure`·`HttpOnly`·`SameSite`.
- 보안 헤더: CSP, `frame-ancestors`, `X-Content-Type-Options`, `Referrer-Policy`.
- 오류 응답에 스택 트레이스와 내부 정보를 숨깁니다.
- Spring Actuator를 외부에 노출하지 않습니다.
- 앞단에 Nginx와 ModSecurity(OWASP CRS) WAF를 Docker로 둡니다.
- 의존성 검사와 SBOM, 이미지 스캔(Trivy), OWASP ZAP 스캔을 합니다.
- 인가 우회 시험: 다른 역할로 접근해 봅니다.

**성격**
- 작은 데모입니다. 하지만 고객에게 서비스될 실제 웹서비스의 일부처럼 만듭니다.
- 마감은 2026-11-19입니다. 구현할 것과 문서로만 남길 것을 먼저 제안해 주세요.
