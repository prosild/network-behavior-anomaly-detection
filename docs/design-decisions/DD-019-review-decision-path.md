# DD-019. 분석가 검토 결정은 DB 함수로 받고, 멈춘 흐름은 파이프라인이 재개한다

- 결정일: 2026-11-19
- 요청·결정: 사용자(Claude 추천안 선택). Q50 2번의 원안(근거 API가 흐름을 직접 재개)을 바꾼다.
- 관련: [DD-002](DD-002-transformer-langgraph-rag.md)(LangGraph), [DD-010](DD-010-ecs-enrichment-incident-lifecycle.md)(사건 상태 흐름), [DD-011](DD-011-gemini-decision-model.md)(판단 모델), [설계 질문 기록](../design-discussion-log.md) Q50, [데이터 계약 v2](../data-contract-v2.md), [단계 6 진행 기록](../stage-6-progress.md) 스물넷째 작업

## 배경
- 판단 모델이 `analyst_review`를 고르면 LangGraph 흐름이 `interrupt()`로 멈추고 상태는 PostgreSQL checkpoint에 남는다. 재개는 명령줄(`scripts/run_agent_graph.py resume`)로만 됐다.
- Q50(2026-11-17)에서는 "근거 API에 검토 결정 경로를 더해 API가 흐름을 재개한다"로 정했다.
- 구현하려고 보니 API가 흐름을 재개하려면 worker 계정(쓰기), LangGraph 상태(사건 사실 목록·보고서), Gemini 키(그래프를 만들 때 필요)를 모두 가져야 한다. 대시보드가 부르는 API가 가장 큰 권한을 갖게 된다. 지금 API는 읽기 전용 계정(`zeekad_api`)만 쓴다.
- 대시보드는 이미 상태 변경을 DB 함수(`dashboard.transition_incident`, `SECURITY DEFINER`)로 한다. 규칙은 함수가 강제하고 대시보드 계정은 함수 실행 권한만 있다.

## 결정
1. 대시보드는 `dashboard.decide_review(job, incident, action, analyst, note)`로 결정만 넣는다([migration 014](../../db/migrations/014_review_decision.sql)). 실행 권한은 `dashboard_rw`와 `zeekad_worker`만 있다.
   - 결정 값은 `confirm`·`dismiss`, 분석가 이름 필수, 검토 요청이 있어야 하고, 한 번만 결정한다(행 잠금).
2. 파이프라인(감시 프로그램)은 주기마다 "결정됐지만 재개 안 됨"(`action IS NOT NULL AND resumed_at IS NULL AND resume_error IS NULL`)을 찾고, 있으면 [scripts/resume_reviews.py](../../scripts/resume_reviews.py)를 부른다. 같은 thread(`작업|사건`)를 그 결정으로 재개한다([zeek_ad/review_resume.py](../../zeek_ad/review_resume.py)).
   - 재개 전에 thread가 정말 `analyst_review`에서 멈춰 있는지 본다. 아니면 `resume_error = 'not_waiting'`.
   - 재개 뒤 흐름이 끝났으면 `resumed_at`을 쓴다. 실패하면 오류 종류만 `resume_error`에 남기고 다시 고르지 않는다(오류 문장에 실제 IP가 섞일 수 있다). 다시 하려면 명령줄 재개를 쓴다.
   - 재개는 MLflow trace 하나로 남긴다(캡처·작업·큐 순위만, IP 없음).
3. 재개된 흐름은 지금 그대로다: `analyst_review` 노드가 결정을 기록하고(대시보드가 넣은 결정 시각은 덮지 않는다), `apply_status`가 상태를 바꾸고(`confirm` → investigating, `dismiss` → investigating → closed(false_positive)) Slack 상태 알림을 남긴다.
4. 근거 API는 읽기 전용 그대로다. 검토 목록 뷰(`dashboard.analyst_review_queue`)에 `zeekad_review_resumed_at`, `zeekad_review_resume_failed` 열을 뒤에 더했다.
5. 014 전에 결정된 검토는 그래프 재개나 일반 함수 버전으로만 결정될 수 있었으므로 재개된 것으로 표시한다([migration 015](../../db/migrations/015_review_backfill.sql), 기준 시각은 014 적용 시각).

## 확인(2026-11-19)
- 시험 [tests/test_review_resume.py](../../tests/test_review_resume.py) 6개(가짜 그래프·DB 규칙 5개, 작은 실제 LangGraph 그래프로 interrupt → 재개 1개). 전체 167개 통과.
- 이 PC DB에서 함수 규칙(되돌리는 트랜잭션 안에서): 정상 결정, 두 번째 결정 거부, 잘못된 값·분석가 없음·요청 없음 거부, `zeekad_api` 실행 거부(`42501`).
- 배포 VM 시연: 재생한 정상 자산(DD-017 A) 사건 하나(작업 41, 1위)를 `dashboard_rw`로 `dismiss` 06:09:42 → 감시 프로그램이 06:09:47에 재개 → 상태 open → investigating → closed(false_positive), 이력의 actor·reason이 결정한 사람·메모, Slack 상태 알림 두 건(dry-run), MLflow trace.

## 알아야 할 한계
- 재개까지 최대 감시 주기(30초) + 재개 시간(약 7초)이 걸린다. 화면은 `zeekad_review_resumed_at`으로 반영을 확인한다.
- 같은 사건이 뒤 작업에서 다시 보고되면 검토 요청이 작업마다 생길 수 있다. 화면은 `zeekad_report_job_id`의 요청만 보여 준다(데이터 계약). 앞 작업의 결정 전 요청은 그대로 남는다.
- 배포 순서: 새 열을 읽는 감시 프로그램보다 migration을 먼저 적용해야 한다. 이번에는 이미지를 먼저 올려 감시 프로그램이 `UndefinedColumn`으로 재시작을 반복했고, 일회용 컨테이너(`docker compose run --rm`)로 migration을 적용해 풀었다.
