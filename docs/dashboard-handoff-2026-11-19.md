# zeek_AD → 대시보드: 2026-11-18~19 변경 사항

대시보드 화면·조회에 영향을 주는 것만 모았다. 배포 VM의 zeekad DB에는 이미 적용됐다(migration 014·015·016).
**기존 뷰의 열 이름·뜻·순서는 바뀌지 않았다.** 몇 개 뷰의 맨 뒤에 열을 더했을 뿐이다. 다만 뷰 열을 위치로 읽는 코드가 있다면 확인이 필요하다.
근거 API(`http://api:8000`)는 읽기 전용 그대로이고 경로도 바뀌지 않았다.

## 1. Slack 기록은 `incident_id`로 찾는다 (규칙 보완)

- 같은 사건의 보고서는 뒤 작업에서 다시 만들어질 수 있다. 실습망 캡처는 5분 파일이 올 때마다 그날을 다시 계산하고, 사건이 늘어나면 보고서도 다시 만든다.
- Slack은 다시 보내지 않으므로, Slack 기록은 **처음 알린 작업에만** 있다.
- 따라서 `dashboard.slack_deliveries`는 `zeekad_report_job_id`나 `job_id`로 조인하지 말고 **`incident_id`만으로** 찾는다.
- 보고서(`incident_reports`), 전송 판단(`send_decisions`), 검토 요청(`analyst_review_queue`)은 전처럼 `latest_incident_queue.zeekad_report_job_id`로 조인한다.

## 2. Slack 알림 묶음(스레드): `dashboard.slack_deliveries`에 열 2개 추가

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `zeekad_thread_parent` | text | 이 알림이 붙는 묶음 머리 사건의 `incident_id`. null이면 채널에 새로 올라간 머리 알림이다. 머리 사건 자신의 뒤 알림(LLM 보고서 추가, 상태 변경)은 자기 `incident_id`를 가리킨다 |
| `zeekad_reply_broadcast` | boolean | 스레드 답글을 채널에도 띄웠는가(재알림) |

- 규칙
  - 같은 호스트·역할에 아직 종료되지 않은 알림 묶음이 있으면 묶습니다. 기준은 사건의 관측 시각으로, 새 사건이 그 묶음의 마지막 사건 끝에서 60분 안에 시작했는가입니다. 이 경우 새 사건 알림은 머리 알림의 Slack 스레드 답글이 된다.
  - 묶음 안에서 마지막으로 채널에 알린 지 30분이 지났으면, 답글을 채널에도 띄운다.
  - 머리 사건이 종료(closed)됐으면 다음 사건은 새 머리 알림이 된다.
  - 조사 큐(사건)는 묶지 않는다. 묶는 것은 Slack 알림뿐이다.
- 2026-11-19 이전 기록은 두 열이 null/false다.
- 화면 제안: Slack 기록을 보여 줄 때 `coalesce(zeekad_thread_parent, incident_id)`로 묶으면 Slack 채널에 보이는 모양과 같아진다.
- 아직 dry-run이다(`zeekad_delivery_mode = 'dry_run'`). 실제로 보내지 않는다.

## 3. 분석가 검토 결정: DB 함수 `dashboard.decide_review` (새로 추가)

전에는 검토 결정을 근거 API의 쓰기 경로로 받을 계획이었다. 이 계획은 쓰지 않는다. API는 읽기 전용으로 두고, 상태 변경과 같은 방식인 DB 함수로 받는다.

| 항목 | 값 |
| --- | --- |
| 계정 | `dashboard_rw` (상태 변경 함수와 같은 계정. 비밀번호는 `DASHBOARD_RW_PASSWORD`) |
| 권한 | 이 함수 실행만. 표에 직접 쓸 수 없다. `dashboard_ro`·`zeekad_api`는 실행할 수 없다(`42501`) |

```sql
SELECT dashboard.decide_review(
    p_job      => 44,                  -- 검토 요청의 job_id (latest_incident_queue.zeekad_report_job_id)
    p_incident => 'lab-20261119|10.10.0.10|responder|1795061700',   -- 실제로 결정 전인 요청(작업 44, 큐 6위)
    p_action   => 'dismiss',           -- 'confirm'(조사 진행) 또는 'dismiss'(오탐으로 종료)
    p_analyst  => 'analyst01',         -- 로그인한 사용자
    p_note     => '정상 업무'            -- 선택. 상태 이력의 reason이 된다
);  -- 반환: 결정 값('confirm' 또는 'dismiss')
```

- 거부(SQLSTATE, 메시지는 한국어 문장이라 그대로 보여 줘도 된다)
  - `22023`: 결정 값이 둘 중 하나가 아님, `p_analyst`가 비었음, 이미 결정한 요청
  - `02000`: 그 작업·사건에 검토 요청이 없음
  - 결정은 한 번뿐이다. 두 사람이 동시에 결정하면 하나만 성공한다(행 잠금).
- 함수는 결정을 기록할 뿐이다. 멈춘 에이전트 흐름은 파이프라인이 주기적으로(30초) 찾아 재개한다. 보통 결정 뒤 10~40초 안에 다음이 일어난다.
  - `confirm`: 사건 상태 open → investigating.
  - `dismiss`: open → investigating → closed(`false_positive`).
  - 상태 이력(`incident_status_history`)의 `actor`는 `p_analyst`, `reason`은 `p_note`(비었으면 "분석가 confirm/dismiss")다.
  - Slack 상태 알림 기록이 추가된다(그 사건 스레드의 답글).
  - 대시보드에서 상태를 먼저 바꿔도 괜찮다. 재개할 때 이미 지난 상태는 건너뛴다.
- `dashboard.analyst_review_queue`에 열 2개 추가

| 열 | 타입 | 뜻 |
| --- | --- | --- |
| `zeekad_review_resumed_at` | timestamptz | 파이프라인이 흐름을 재개해 끝낸 시각. 결정했지만 아직이면 null |
| `zeekad_review_resume_failed` | boolean | 재개 실패. 파이프라인 운영자가 명령줄로 다시 재개한다 |

- 화면 제안
  - 결정 버튼은 `zeekad_review_action IS NULL`인 요청에만 보여 준다.
  - 같은 사건의 요청이 여러 작업에 있으면 `zeekad_report_job_id`의 요청만 보여 준다.
  - 결정 뒤 `zeekad_review_resumed_at`이 null이면 "반영 중", 값이 있으면 "반영됨", `zeekad_review_resume_failed`면 "반영 실패(운영자 확인)"로 보여 준다.
- 지금 배포 VM에는 결정 전 검토 요청이 10건 있다(`lab-20261119`). 시험해 볼 수 있다.

## 4. 모델 묶음 교체: 결합 v2, champion = `zeekad-fusion/3`

- 2026-11-19부터 새 채점 작업은 Registry 버전 3(결합 규칙 v2)을 쓴다. 작업의 `bundle_id`(`dashboard.scoring_jobs`, `incident_queue`)로 어느 버전인지 안다. 버전 정보는 `dashboard.model_bundles`에 있다.

  | `bundle_id` | 결합 규칙 | 비고 |
  | --- | --- | --- |
  | `zeekad-fusion/1` | v1 | 2026-11-12 코드. 작업 42까지 |
  | `zeekad-fusion/2` | v1 | 같은 규칙을 현재 코드로 다시 만든 것. 되돌릴 때 쓴다(작업 43) |
  | `zeekad-fusion/3` | v2 | 현재 champion(작업 44부터) |

- v2에서 바뀐 사건의 뜻(뷰 구조는 같다)
  - 여러 모델이 같은 호스트·역할을 겹쳐 꼽으면 한 사건으로 합친다.
  - 사건의 창(`incident_model_scores`, 근거)은 겹쳐 꼽은 모든 모델 창의 합이다. v1은 처음 뽑은 모델의 창만 썼다.
  - `picked_by`는 큐에서 처음 뽑은 모델, `also_flagged_by`는 겹쳐 꼽은 다른 모델이다(전과 같음).
  - 합친 사건은 30분보다 길 수 있다. 화면이 사건 길이를 30분 이하로 가정했다면 고친다.
  - `incident_id`는 합친 범위의 첫 창으로 만든다.
- 같은 캡처·같은 입력에 묶음만 다른 작업이 생길 수 있다(교체·롤백 시연 때 생겼다). "캡처의 최신 작업 = 가장 큰 `job_id`" 규칙은 그대로다.
- 되돌릴 때는 파이프라인 쪽에서 alias만 바꾼다. 대시보드가 할 일은 없다.

## 5. 실습망 시험 데이터 표시 주의 (`lab-20261119`)

이날 캡처에는 시험용으로 다시 틀거나 만든 정상 트래픽이 섞여 있다. 화면에 표시를 붙일지는 대시보드 쪽 판단이다.

| 호스트 | 정체 |
| --- | --- |
| `10.10.0.100` ~ `10.10.0.112` | CIC-IDS-2017 월요일(정상) 트래픽을 주소만 바꿔 재생한 가상 호스트 |
| `10.10.0.11`, `10.10.0.12`, `10.10.0.53` | 스크립트로 만든 정상 클라이언트·DNS(가상) |
| `10.10.0.50` | Kali(실제 공격 VM) |
| `10.10.0.10` | 배포 VM(실제 호스트, 공격 대상) |

04:00 UTC 칸의 짧은 사건 여러 건은 재생 시험(10초)으로 생긴 것이다.

## 5-1. 새 뷰: 분석가 결론 집계 `dashboard.feedback_summary` (migration 017)

캡처 × 묶음 버전 × 처음 뽑은 모델(`zeekad_picked_by`, 전체는 `'all'`)별로 다음을 센다. `dashboard_ro`가 읽을 수 있다.
- 사건 수(`incidents`), 알린 수(`alerted`), 결론 난 수(`resolved`)
- 결론별 수: `true_positive`·`false_positive`·`benign`
- `zeekad_precision`: 실제 공격 ÷ 결론 난 사건
- `zeekad_alert_precision`: 알린 사건 중 결론 난 것에서의 실제 공격 비율
- `zeekad_alert_resolved_rate`: 알린 사건 중 결론 난 비율

결론이 없으면 정밀도는 null이다. 놓친 공격(재현율)은 이 집계로 알 수 없다.
화면 제안: 정밀도 옆에 결론 수와 결론 비율을 같이 보여 준다(예: "정밀도 0.60, 결론 5/18"). 결론이 적으면 정밀도를 믿기 어렵기 때문이다.
지금 배포 VM의 `lab-20261119`(`zeekad-fusion/3`, 전체)는 사건 52, 알림 18, 결론 1(오탐)이다.

## 6. 대시보드 쪽 확인 목록

1. Slack 기록 조회를 `incident_id` 기준으로 바꿨는가(1번).
2. 검토 결정 버튼이 `dashboard.decide_review`를 `dashboard_rw`로 부르는가. 반영 상태 표시가 있는가(3번).
3. Slack 기록 화면이 스레드 열을 쓰거나 무시해도 깨지지 않는가(2번).
4. 사건 길이 30분 가정, 뷰 열을 위치로 읽는 코드가 없는가(4번, 머리말).
