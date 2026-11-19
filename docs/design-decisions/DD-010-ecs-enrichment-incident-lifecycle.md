# DD-010. 보안 강의 원칙 반영: ECS 필드 이름, Zeek 관측 기반 자산 정보, 사건 상태 흐름, 알림 중복 억제

- 결정일: 2026-11-12
- 요청·결정: 사용자(설계 질문 기록 Q39, "반영해"). 사용자가 수강 중인 보안 강의 요약(docs/security-course-all-session-summary.md)과 사용자 계획(docs/zeek-ad-enterprise-security-integration.md)을 Claude가 검토해 고른 네 가지다.
- 관련: [DD-001](DD-001-slack-delivery-jev-gate.md), [DD-002](DD-002-transformer-langgraph-rag.md), 설계 7.1·9.1절

## 결정

| 항목 | 단계 | 내용 |
| --- | --- | --- |
| ECS 필드 이름 | 4 | 근거 API 응답은 ECS 이름(`host.ip`, `source.ip`, `destination.port`, `network.transport`, `event.start`)을 쓴다. 대시보드 뷰는 같은 이름을 밑줄로 쓴다(`host_ip`, `event_start`). 이 프로젝트만의 값은 `zeekad_` 접두사(`zeekad_role`). 대응표는 [데이터 계약](../data-contract-v1.md)에 있다 |
| 자산 정보 | 4 | Zeek 로그에 실제로 있는 값만 쓴다: kerberos `client`(기계 계정 `NAME$`, 사용자 계정), ntlm `hostname`·`username`. 값마다 출처 로그·관측 수·처음·마지막 시각을 남긴다. 없으면 비워 둔다. 관측하지 않은 값(가상의 호스트명·사용자, 빈 EDR 칸)을 만들지 않는다 |
| 사건 상태 흐름 | 5 | 열림 → 확인 중 → 종료. 역방향과 건너뛰기를 막고 전이마다 누가·언제·왜를 남긴다 |
| 알림 중복 억제 | 5 | 같은 자산·역할에 미해결 알림이 60분 안에 있으면 새 알림을 그 알림에 합친다. 재알림은 30분 간격 이상. 조사 큐(사건)는 억제하지 않는다(DD-001) |

## 하지 않는 것

- 차단·격리 실행과 그 롤백(DD-001: 공격 확정·차단은 사람). 위험 등급 모델.
- 룰 기반 탐지기(DGA, NXDOMAIN, TCP 플래그), IQR·EMA·시간대별 기준선, JA3/JA4(Zeek 재처리·재학습 필요).
- 사용자명·호스트명을 LLM에 보내는 것(설계 9.1절 입력 허용 목록). 자산 정보는 API·대시보드용이다.

## 구현: 알림 중복 억제(결정 5, 2026-11-19)

결정 5의 문장을 구현하면서 정한 세부다(결정은 바꾸지 않았다). [단계 6 진행 기록](../stage-6-progress.md) 스물다섯째 작업.
- 시간 기준: 알림을 만든 시각이 아니라 사건의 관측 시각이다. 다시 계산이 밀려도(실습망 실행 2) 묶음이 흔들리지 않는다.
- "60분 안": 같은 자산·역할 묶음의 마지막 관측 끝에서 새 사건의 첫 창까지 60분 이하. 묶음이 이어지면 창도 밀려간다.
- "미해결": 묶음 머리 사건이 종료(`closed`)가 아니다. 종료됐으면 새 머리 알림이다.
- "합친다": Slack 스레드 답글. 머리 알림이 채널에 한 번 올라가고, 뒤 사건은 그 스레드에 붙는다(채널 알림 없음). 같은 사건의 뒤 알림(LLM 보고서 추가)과 상태 변경 알림도 그 스레드의 답글이다.
- "재알림은 30분 간격 이상": 묶음 안에서 마지막으로 채널에 올라간 알림(머리 또는 재알림)에서 30분이 지났으면 답글을 채널에도 띄운다(Slack `reply_broadcast`). 길게 이어지는 활동도 30분마다 다시 보인다.
- 구현: [zeek_ad/slack.py](../../zeek_ad/slack.py) `group_alert`(규칙, 표준 라이브러리)·`alert_thread`(DB에서 앞선 알림 모으기)·`record_delivery`(설정에 grouping이 있을 때), [configs/agent/slack.v2.json](../../configs/agent/slack.v2.json)(`window_minutes` 60, `realert_minutes` 30, LangGraph가 쓴다. 배치 도구는 v1 그대로), [migration 016](../../db/migrations/016_slack_threads.sql)(`slack_delivery.thread_parent`·`reply_broadcast`, 뷰 두 열).
- 실습망 2026-11-19 알림에 모의로 적용: 사건 알림 20건 → 채널 17건(새 알림 14, 재알림 3), 조용한 답글 3건. 줄어든 것은 같은 호스트가 되풀이된 경우(Kali·배포 VM)다. 이날 알림 대부분은 서로 다른 재생 자산(DD-017 A)이라 자산 단위 묶음으로는 줄지 않는다.
