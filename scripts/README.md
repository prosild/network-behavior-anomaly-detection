# 스크립트 안내

모두 프로젝트 루트에서 `zeek-ad` 환경으로 실행한다(예: `python scripts/run_zeek.py --help`). 스크립트마다 맨 위 설명에 입력·출력·예시가 있다.
경로가 Compose·Dockerfile·감시 프로그램·평가 동결 목록에 들어 있어서 폴더를 나누지 않고 여기서 단계별로 안내한다.

## 1. 데이터 처리 (단계 0\~2)

PCAP → Zeek → Silver → Gold → 그래프 순서로 만든다.

| 스크립트 | 하는 일 |
| --- | --- |
| [check_inputs.py](check_inputs.py) | 원본 입력 경로·크기 확인(내용은 읽거나 바꾸지 않음) |
| [capture_bounds.py](capture_bounds.py) | 원본 PCAP마다 패킷 시각의 최솟값·최댓값을 재서 manifest로 남긴다 |
| [run_zeek.py](run_zeek.py) | PCAP 하나를 Zeek로 처리하고 입력·설정·출력을 잇는 실행 manifest를 남긴다 |
| [inspect_conn.py](inspect_conn.py), [inspect_role_windows.py](inspect_role_windows.py) | conn.log 품질, 자산·역할별 창 수 확인(쓰지 않음) |
| [build_silver_conn.py](build_silver_conn.py) | conn.log → Silver Parquet(PySpark, 명시적 스키마) |
| [build_gold.py](build_gold.py) | Silver → Gold v1(5분 창, conn 특징 18개) |
| [build_gold_v2.py](build_gold_v2.py) | Gold v2 = v1 + Zeek 프로토콜 로그 특징 24개 |
| [check_gold_sample.py](check_gold_sample.py) | Gold 창 몇 개를 Silver 원래 행에서 다시 계산해 대조 |
| [build_sequences.py](build_sequences.py) | Gold 창 → Transformer 입력 시퀀스 |
| [build_tgn_events.py](build_tgn_events.py), [build_tgn_dataset.py](build_tgn_dataset.py) | 연결 이벤트 표 → TGN 시간 그래프 데이터 |
| [build_ground_truth.py](build_ground_truth.py) | 동결한 정답 에피소드 조건을 Silver에 실행해 연결·창 대응표를 만든다(평가 전용) |
| [build_synthetic_zeek.py](build_synthetic_zeek.py) | 합성 APT 패턴을 화\~금 Zeek 로그 사본에 주입(DD-008) |
| [build_eda_part1.py](build_eda_part1.py), [build_eda_part2.py](build_eda_part2.py) | EDA 그림과 통계([docs/eda-design-evidence.md](../docs/eda-design-evidence.md)) |
| [draw_architecture.py](draw_architecture.py) | README 구조도(`docs/figures/architecture.png`) |

## 2. 학습·평가 (단계 3)

| 스크립트 | 하는 일 |
| --- | --- |
| [run_baselines.py](run_baselines.py) | 꼬리 희귀도·Isolation Forest를 월요일로 적합하고 화\~금을 Recall@N으로 평가 |
| [run_transformer.py](run_transformer.py) | Transformer 학습·평가(DD-002) |
| [run_tgn.py](run_tgn.py) | TGN 학습·평가(DD-007) |
| [run_fusion.py](run_fusion.py) | 세 모델 결합 평가(DD-009) |
| [run_synthetic_eval.py](run_synthetic_eval.py) | 다시 학습하지 않고 합성 캡처에 점수를 매겨 평가(DD-008) |
| [build_nat_diagnostic.py](build_nat_diagnostic.py), [build_new_peer_baseline.py](build_new_peer_baseline.py), [build_first_seen.py](build_first_seen.py), [run_detector.py](run_detector.py) | 진단용 자명한 기준선·행동 탐지기(DD-006) |
| [diagnose_long_connections.py](diagnose_long_connections.py) | 긴 연결이 상위 점수 창을 차지하는지 진단 |
| [summarize_eval.py](summarize_eval.py) | 모델별 Recall@N과 bootstrap 95% 구간 표 |
| [check_lab_truth.py](check_lab_truth.py) | 실습망 정답 설정(lab-attacks.v1)의 관측값이 로컬 conn 로그에 규칙을 적용한 결과와 같은지 확인(평가 전용) |
| [build_lab_detection.py](build_lab_detection.py) | VM DB 내보내기로 실습망 공격 종류별 탐지 여부·걸린 시간 표(`detection.json`·`detection.md`, 비율은 내지 않음) |

## 3. 저장·배포·MLOps (단계 4·7)

| 스크립트 | 하는 일 |
| --- | --- |
| [make_env.py](make_env.py) | `deploy/.env`를 무작위 비밀번호로 만든다(덮어쓰지 않음) |
| [db_migrate.py](db_migrate.py) | `db/migrations/*.sql`을 번호 순서로 적용하고 해시를 남긴다 |
| [add_dashboard_rw.py](add_dashboard_rw.py), [add_dashboard_app.py](add_dashboard_app.py) | 이미 초기화된 DB에 대시보드 계정·DB를 더한다 |
| [migrate_mlflow_to_pg.py](migrate_mlflow_to_pg.py), [mlflow_ui.py](mlflow_ui.py) | MLflow 백엔드를 PostgreSQL로 옮기기(한 번), MLflow 화면 |
| [build_bundle.py](build_bundle.py) | 배포 묶음을 만들고 CIC 5일 재현 검사(`--fusion`으로 결합 설정 선택) |
| [register_bundle.py](register_bundle.py) | 묶음을 Registry 새 버전으로 등록, `--set-alias`로 승격·롤백 |
| [check_bundle.py](check_bundle.py) | alias가 가리키는 묶음으로 실제 추론해 저장된 작업과 비교(DB에 쓰지 않음) |
| [run_worker.py](run_worker.py) | Registry 묶음으로 캡처를 채점하고 결합 큐를 DB에 쓴다 |
| [test_worker_recovery.py](test_worker_recovery.py), [verify_worker_db.py](verify_worker_db.py) | worker 장애 복구 시험, DB 결과가 단계 3 평가와 같은지 확인 |
| [build_evidence.py](build_evidence.py) | 사건 근거 요약과 자산 관측을 DB에 쓴다 |
| [run_api.py](run_api.py), [check_api.py](check_api.py) | 근거 조회 API(읽기 전용) 띄우기와 계약 확인 |

## 4. 에이전트 (단계 5)

RAG, LLM 보고서, 전송 판단, LangGraph를 다룬다.

| 스크립트 | 하는 일 |
| --- | --- |
| [build_attack_corpus.py](build_attack_corpus.py), [embed_attack_docs.py](embed_attack_docs.py) | MITRE ATT&CK 문서를 DB에 넣고 임베딩 |
| [eval_rag_retrieval.py](eval_rag_retrieval.py) | 검색 방법을 고정 질의 세트로 비교 |
| [build_agent_inputs.py](build_agent_inputs.py) | 사례 사건마다 LLM 입력(허용 목록·가명), 검색 결과, 템플릿 보고서 |
| [run_agent_reports.py](run_agent_reports.py) | LLM 보고서와 검증, 실패하면 템플릿 |
| [run_send_decisions.py](run_send_decisions.py), [score_send_decisions.py](score_send_decisions.py) | Slack 전송 판단 세 방식 그림자 비교와 정답 기준 채점 |
| [load_agent_results.py](load_agent_results.py), [backfill_report_facts.py](backfill_report_facts.py) | 파일 결과를 DB로 옮기기, 예전 보고서에 사실 목록 채우기(한 번) |
| [run_slack.py](run_slack.py) | 보낼 사건의 Slack 메시지 기록(dry-run) |
| [run_agent_graph.py](run_agent_graph.py) | 사건 하나를 LangGraph 흐름으로 처리(`start`·`status`·`resume`) |
| [compare_agent_versions.py](compare_agent_versions.py) | 일반 함수 버전과 LangGraph 버전 비교 |
| [resume_reviews.py](resume_reviews.py) | 대시보드에서 결정한 분석가 검토로 멈춘 흐름 재개(DD-019) |

## 5. 실습망 실시간 처리 (단계 6, 배포 VM)

| 스크립트 | 하는 일 |
| --- | --- |
| [capture_lab.sh](capture_lab.sh), [capture_rotate.sh](capture_rotate.sh) | 수집기: 실습망 카드만 캡처, 5분 시계 경계마다 파일을 수신 폴더로 |
| [move_rotated.sh](move_rotated.sh) | (예전 방식) tcpdump `-z`로 다 쓴 파일을 수신 폴더로 옮기기 |
| [live_watcher.py](live_watcher.py) | 감시 프로그램: 새 파일 → Zeek → 그날 다시 계산 → 에이전트 → 검토 재개 |
| [live_recompute.py](live_recompute.py) | 그날 받은 파일 전체로 Silver\~채점\~근거를 다시 계산(리비전), 오래된 리비전 정리 |
| [live_agent.py](live_agent.py) | 최신 채점 작업의 새·늘어난 사건을 LangGraph로 처리 |
| [prune_revisions.py](prune_revisions.py) | 지난 날짜의 리비전 폴더 정리 |
| [lab_scenario.sh](lab_scenario.sh) | Kali 시험 시나리오(5분 칸마다 활동 하나: ping·nmap) |
| [lab_beacon.sh](lab_beacon.sh) | 비커닝(C2 신호) 생성기: 침해 호스트가 C2에 고정 간격(+지터)으로 짧은 연결 반복(DD-020). 여러 창에 걸친 조용한 공격 |
| [lab_normal_client.sh](lab_normal_client.sh) | 타깃 정상 배경 생성기: 여러 목적지·포트에 불규칙한 간격으로 웹 요청(DD-020). 비커닝과 대비되는 originator 기준 |
| [lab_exfil.sh](lab_exfil.sh) | 느린 유출 생성기: 침해 호스트가 C2로 큰 데이터를 창마다 나눠 올림(DD-020, DD-008 slow_exfil의 실제 버전). 연결은 적고 바이트가 큰 유형 |
| [lab_lateral.sh](lab_lateral.sh) | 측면 이동 생성기: pivot이 여러 내부 호스트의 SMB(445)로 퍼짐(DD-020). 여러 호스트의 한 포트 fan-out, TGN(관계적 이상) 시험 |
| [lab_bruteforce.sh](lab_bruteforce.sh) | SSH 무차별 대입 생성기: 타깃 22에 연결·인증을 빠르게 반복(DD-020, TA0006). 한 호스트 한 포트에 연결 쏟아지는 유형 |
| [lab_dns_tunnel.sh](lab_dns_tunnel.sh) | DNS 터널 생성기: 질의자가 C2 도메인의 긴 무작위 하위 도메인을 DNS 서버에 질의(DD-020, DD-008 dns_tunnel의 실제 버전). 흔한 프로토콜에 숨는 조용한 유형 |
| [build_lab_background.py](build_lab_background.py), [lab_replay.sh](lab_replay.sh) | 정상 배경 PCAP 만들기와 재생(DD-017) |
