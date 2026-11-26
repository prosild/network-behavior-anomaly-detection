# 문서 안내

처음이면 [저장소 README](../README.md) → [한 장 요약](portfolio-summary.md) 순서로 읽는다. 나머지 문서는 주제별로 나눴다.

## 설계

| 문서 | 내용 |
| --- | --- |
| [FINAL_PROJECT_DESIGN.md](../FINAL_PROJECT_DESIGN.md) | 구현 기준인 최종 설계. 2.2절 표에 이후 설계 결정(DD) 목록이 있다. DD가 본문보다 우선한다 |
| [design-decisions/](design-decisions/) | 설계 결정 DD-001\~021. 결정마다 배경, 결정, 확인한 것, 한계를 적었다 |
| [design-discussion-log.md](design-discussion-log.md) | 설계 질문·이의와 판단 근거(Q1\~). 설계를 바꾸지 않은 경우도 적었다 |
| [IMPLEMENTATION_CHECKLIST.md](../IMPLEMENTATION_CHECKLIST.md) | 단계별 검증 조건(V1\~V7) |
| [final-design-verification-results.md](../final-design-verification-results.md) | 설계 확정 전 독립 검증 결과(2026-11-03) |
| [project-architecture-mermaid.md](project-architecture-mermaid.md) | 파이프라인과 DB 구조도(2026-11-13 기준. 이후 바뀐 것은 README 구조도와 DD-012\~021) |

## 데이터·특징·정답

| 문서 | 내용 |
| --- | --- |
| [data-usage-terms.md](data-usage-terms.md) | CIC-IDS2017·개선 라벨·MITRE ATT&CK 이용 조건과 인용 |
| [observation-meaning.md](observation-meaning.md) | 공격 후보 하나와 정상 비교 하나를 Zeek 관측으로 읽는 법 |
| [eda-design-evidence.md](eda-design-evidence.md) | EDA 결과와 설계 근거(그림 [figures/eda/](figures/eda/)) |
| [feature-dictionary-v1.md](feature-dictionary-v1.md), [feature-dictionary-v2.md](feature-dictionary-v2.md) | 특징 사전(v1 conn 18개, v2는 프로토콜 로그 24개를 더한 42개) |
| [ground-truth-v1.md](ground-truth-v1.md) | 정답 에피소드를 만든 방법과 목록(평가 전용) |
| [lab-attack-detection.md](lab-attack-detection.md) | 실습망 Kali 공격 8종(11회)을 종류별로 잡았는지와 첫 알림까지 걸린 시간, 판정 기준 |

## 운영

| 문서 | 내용 |
| --- | --- |
| [vm-deployment.md](vm-deployment.md) | VMware 배포 VM과 Kali 실습망을 처음부터 만드는 순서, 자주 쓰는 명령, 모델 교체·롤백 |
| [live-pipeline.md](live-pipeline.md) | 파일 단위 자동 파이프라인의 동작 원리와 켜는 법 |

## Java 관리자 대시보드 연동

대시보드는 별도 저장소 [zeek_ad_dashboard](https://github.com/prosild/zeek_ad_dashboard)에 있다.

| 문서 | 내용 |
| --- | --- |
| [data-contract-v2.md](data-contract-v2.md) | 현재 계약. 대시보드가 읽는 뷰와 쓰는 DB 함수(상태 변경, 검토 결정), 결론 집계 |
| [data-contract-v1.md](data-contract-v1.md) | 첫 계약(v2가 이어받음) |
| [java-admin-dashboard-requirements.md](java-admin-dashboard-requirements.md) | 대시보드 요구사항 |
| [java-dashboard-agent-brief.md](java-dashboard-agent-brief.md) | 대시보드를 만드는 쪽에 준 안내 |
| [dashboard-handoff-2026-11-19.md](dashboard-handoff-2026-11-19.md) | 2026-11-18\~19 변경 사항 전달 |
| [dashboard-handoff-2026-11-21.md](dashboard-handoff-2026-11-21.md) | 2026-11-21 변경 사항 전달(모델·수집 구간 표시 이름, LLM 요청 모델) |
| [dashboard-handoff-2026-11-23.md](dashboard-handoff-2026-11-23.md) | 2026-11-23 Slack 스레드 열 질문 회신(도입 전 기록의 null, 새 캡처 표시) |
| [dashboard-handoff-2026-11-26.md](dashboard-handoff-2026-11-26.md) | 2026-11-26 외부 피드백 회신(Kali 공격 정답 기록, 탐지 여부·걸린 시간 표, 정탐 예시 사건) |

## 진행 기록

단계마다 한 일, 실행 결과, 발견한 문제를 적었다.

| 문서 | 단계 |
| --- | --- |
| [stage-0-progress.md](stage-0-progress.md) | 0. 입력 검사, 내부 자산 판정, 5분 창과 학습/보류 분할, 실행 환경 |
| [stage-1-progress.md](stage-1-progress.md) | 1. Zeek 실행 환경 고정과 재현, 5일 Zeek 처리 |
| [stage-2-progress.md](stage-2-progress.md) | 2. Bronze → Silver(PySpark), 캡처 시각 범위, 역할과 창 라벨, 특징 사전 |
| [stage-3-progress.md](stage-3-progress.md) | 3. 정답 에피소드, 평가기, 기준선·IF, Transformer, TGN, 합성 APT, 결합 |
| [stage-4-progress.md](stage-4-progress.md) | 4. PostgreSQL, MLflow Registry 배포 묶음, 추론 worker와 장애 복구, 근거 API |
| [stage-5-progress.md](stage-5-progress.md) | 5. ATT&CK RAG, LLM 보고서·검증, 전송 판단, Slack dry-run, LangGraph, 사건 상태 |
| [stage-6-progress.md](stage-6-progress.md) | 6. 파일 단위 자동 파이프라인, VMware 배포, 실습망 Kali 시험과 정상 배경 |
| [stage-7-progress.md](stage-7-progress.md) | 7. 모델 교체·롤백 시연, 분석가 결론 집계 |
| [session-handoff.md](session-handoff.md) | 지금 위치와 남은 일(작업 세션 사이의 인계) |
