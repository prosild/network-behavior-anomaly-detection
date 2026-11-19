# 단계 7 진행 기록: 모델 교체·재적재·롤백

기준: [최종 설계](../FINAL_PROJECT_DESIGN.md) 8절("새 작업 경계에서 묶음을 적재하고 실제 사용 버전·샘플 추론·스키마를 확인한다. 이전 묶음 복원 후 실제 추론 버전까지 확인해야 롤백 완료다"), [체크리스트](../IMPLEMENTATION_CHECKLIST.md) V6("alias 변경 화면만으로 롤백 시연을 완료하지 않는다").

## 첫째 작업: 결합 v2 묶음 등록, 교체·롤백 시연(2026-11-19, 배포 VM)

### 시작할 때 발견한 문제
- 결합 v2([DD-018](design-decisions/DD-018-fusion-merge-overlaps.md))와 검토 경로(DD-019) 배포 때 `zeek_ad/fusion.py`·`bundle.py`를 VM에 올렸다. 채점 worker는 묶음 manifest의 코드 해시와 지금 코드가 같아야 묶음을 쓴다([zeek_ad/worker.py](../zeek_ad/worker.py) `resolve_bundle`). 그래서 champion(버전 1)이 "묶음을 만든 뒤 코드가 바뀌었다"로 거부되는 상태였다. 이때 실습망 파일이 들어왔으면 채점이 실패했다.
- 그 사이 트래픽이 없어 실패한 작업은 0건이다(확인). 배포할 때 묶음 코드 파일을 바꾸면 묶음도 새 버전으로 등록해야 한다는 것을 놓쳤다.
- 등록 중 하나 더: VM의 `evaluation.py`가 이 PC와 달랐다(스무째 작업에서 docstring 세 줄만 고치고 VM에 올리지 않음). 등록 스크립트가 같은 검사로 막았고, 파일을 맞춘 뒤 등록했다.

### 규칙(설계 8절 그대로, 이번에 도구로 만듦)
- 코드가 바뀌면 묶음을 다시 만들고, CIC 다섯 캡처의 창 점수가 원래 평가와 같은지 재현 검사를 통과해야 새 버전으로 등록한다. 버전 1은 이전 코드용으로 남는다.
- 승격은 손으로 한다. 묶음을 만들 때 champion을 자동으로 붙이지 않는다.
- 채점 작업은 시작할 때 alias를 버전 번호로 고정한다. 작업 = 입력 + 묶음이라 한 작업 안에 두 버전 점수가 섞이지 않는다.

### 바꾼 것
- [scripts/build_bundle.py](../scripts/build_bundle.py): `--fusion`(결합 설정 선택, 묶음 폴더 `outputs/bundles/<설정 ID>/<시각>/`), `reproduction.json`, 자동 champion 지정 제거(`--alias`를 줄 때만).
- [scripts/register_bundle.py](../scripts/register_bundle.py)(새 파일): 묶음 폴더를 Registry 새 버전으로 등록(재현 통과·코드 해시 확인 뒤), `--set-alias ALIAS VERSION`(승격·롤백). 이 PC와 VM에서 같은 방법으로 쓴다(VM에는 재현에 쓰는 CIC 자료가 없다).
- [scripts/check_bundle.py](../scripts/check_bundle.py)(새 파일): alias가 가리키는 묶음으로 실제 추론을 하고 저장된 작업과 비교한다. DB에 쓰지 않는다. 같은 입력의 작업이 이미 있으면 worker는 건너뛰므로 롤백 확인에 쓴다.
- [scripts/live_agent.py](../scripts/live_agent.py) `revision_for_job`: 작업의 리비전 폴더를 `pipeline.json`의 작업 번호가 아니라 입력 지문(`scoring_job.input_manifest_sha256`)으로 찾는다. 묶음을 바꿔 같은 리비전을 다시 채점한 작업을 찾지 못하던 문제(작업 44). 시험 1개 추가, 전체 178개 통과.

### 묶음과 버전(이 PC와 VM 같음)

| Registry 버전 | 결합 설정 | 코드 | 재현(CIC 5캡처 창 점수 최대 차이) |
| --- | --- | --- | --- |
| 1 | fusion.v1 | 11-12 코드 | 0(단계 4) |
| 2 | fusion.v1 | 11-19 코드 | 0 |
| 3 | fusion.v2(merge_windows) | 11-19 코드 | 0 |

### 시연(배포 VM, 실습망 `lab-20261119`의 최신 리비전 rev-0014)
1. champion 1 → 2. 같은 입력으로 새 작업 43(`zeekad-fusion/2`): 작업 42(`zeekad-fusion/1`)와 창 점수 567행·사건 52건(순위·ID·모델·점수·창)이 모두 같다. 코드를 바꿔도 v1 규칙의 결과는 그대로다.
2. 교체: champion 2 → 3. 새 작업 44(`zeekad-fusion/3`): 창 점수는 같고, 여러 모델이 겹쳐 꼽은 사건 둘만 합쳐졌다(1위 재생 자산 창 2 → 3, 6위 배포 VM 창 2 → 5). DD-018의 사후 계산과 같다.
3. 롤백: champion 3 → 2. `check_bundle.py`로 실제 추론: `zeekad-fusion/2`(overlap_policy skip)가 작업 43과 같고 작업 44와는 사건이 다르다.
4. 다시 champion 2 → 3, 실제 추론이 작업 44와 같다. **최종 champion은 버전 3(결합 v2)**. 이 PC 등록소도 같게 맞췄다.
5. 에이전트(작업 44): 범위가 바뀐 사건 2건만 다시 처리했다(늘어난 사건). LLM 보고서 2건 검증 통과, 판단 모델은 둘 다 analyst_review. 합친 배포 VM 사건(04:15~04:40)의 보고서는 Kali 스캔(572개 포트, REJ 622건)과 B 클라이언트의 HTTP(각 147건)를 함께 설명한다. 합친 사건에 정상 배경 창이 붙는 DD-018 한계가 실제 보고서에 드러났다. 이미 알린 사건이라 Slack은 다시 보내지 않았다.

### 남은 것·한계
- 대시보드 쪽에 알릴 내용(Slack 조인 규칙, 스레드 열, 검토 결정 함수, 결합 v2와 묶음 버전, 시험 데이터 호스트)은 [dashboard-handoff-2026-11-19.md](dashboard-handoff-2026-11-19.md)에 모아 사용자에게 넘겼다.
- 새 실습망 트래픽이 들어오면 감시 프로그램이 다시 계산하고 champion(버전 3)으로 채점한다. 그때 알림 묶음(DD-010 결정 5)의 실제 기록도 확인한다.
- 승격 조건 중 메모리·지연 측정과 장애 복구 통과는 이번 버전 비교에서 따로 재지 않았다(창 점수가 같고 결합 규칙만 다르다. worker 장애 복구 시험은 단계 4 `scripts/test_worker_recovery.py`).
- 묶음의 `pip_requirements`는 pandas 2.3.3이고 환경은 3.1.0이다(Q52 5번, 미룸). 재현 차이는 0이다.

## 둘째 작업: 분석가 결론 집계와 README 보완(2026-11-19, Q61)

- 배경: 실제 환경에는 라벨이 없다(Q61). 운영에서 쌓이는 유일한 라벨은 분석가의 종료 결론인데, 기록만 하고 집계하지 않았다. 설계 8절의 운영 관측 항목 중 하나다.
- [db/migrations/017_feedback_summary.sql](../db/migrations/017_feedback_summary.sql): 뷰 `dashboard.feedback_summary`(캡처 × 묶음 버전 × 처음 뽑은 모델, 전체 행 `'all'`). 사건 수, 알린 수, 결론 수·결론별 수, 정밀도, 알린 사건의 정밀도, 알린 사건 중 결론 비율. `dashboard_ro`·`zeekad_api`가 읽는다.
- 확인: 이 PC DB(금요일 CIC 알림 9건 중 결론 1건 오탐, 결론 비율 0.111). 배포 VM(migration 먼저 적용): `lab-20261119`(`zeekad-fusion/3`) 사건 52, 알림 18, 결론 1(오탐, 스물넷째 작업 시연), 정밀도 0.000, 결론 비율 0.056.
- 한계: 놓친 공격(재현율)은 알 수 없다. 결론이 적으면 정밀도를 믿기 어렵다(결론 비율을 같이 본다). 결론을 임계값 조정에 쓰는 고리, 점수 분포·알림 수 감시, 새 환경 임계값 재설정은 없다.
- [README.md](../README.md)에 "라벨 없는 실제 환경에서의 의미" 절을 더했다. [데이터 계약 v2](data-contract-v2.md)와 [대시보드에 알릴 글](dashboard-handoff-2026-11-19.md)에 새 뷰를 더했다.
