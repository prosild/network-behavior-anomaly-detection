# 세션 인계 (2026-11-19 기준)

새 세션은 AGENTS.md(로컬 작업 안내, 저장소에 없음)의 "먼저 읽을 문서"와 이 파일을 읽고 시작한다. 단계별 세부는 진행 기록([단계 3](stage-3-progress.md)\~[단계 7](stage-7-progress.md))에 있다. 문서 전체 안내는 [docs/README.md](README.md). 마감 제약은 고려하지 않는다(사용자 지시).

## 지금 위치
- **배포 VM에서 처음부터 끝까지 돈다(DD-015, 2026-11-18)**: Kali → 실습망(VMnet2) 캡처 → Zeek → 그날 다시 계산(Silver → Gold → 그래프 → 세 모델 채점 → 결합 큐 → 근거) → LangGraph(템플릿 알림 → LLM 보고서 → 판단 모델 → Slack dry-run). 만드는 법은 [vm-deployment.md](vm-deployment.md), 결과는 [단계 6 진행 기록](stage-6-progress.md) 열셋째 작업부터.
- **VM 첫 실행 뒤 수정([DD-016](design-decisions/DD-016-lab-capture-coverage-and-report-refresh.md), 열넷째·열다섯째 작업)**: 수집은 5분 시계 경계마다 파일을 넘기고 덮은 시간을 이름에 넣는다. 캡처 경계 끝은 관측을 마친 시각까지. 사건이 늘어나면(창 목록이 달라지면) 보고서·판단을 다시 만들고, 이미 알린 사건은 Slack에 다시 보내지 않는다.
- **프로젝트 검토 Q57의 결함 수정(열여섯째\~열아홉째 작업)**: 에이전트 사건별 실패 격리와 다시 시도, LLM 응답 형식 검사(동결 파일 밖), MLflow trace에 예외 문장 안 남기기, 처리 중 끊긴 수신 파일 이어 하기. 결함 4(평가 집계의 여러 날 사건)는 한계로 기록.
- **리비전 정리(스물한째 작업)**: 다시 계산이 성공하면 그날 성공 리비전 최신 2개와 그보다 새로운 것만 남긴다. 지난 날짜는 `scripts/prune_revisions.py`. DB는 지우지 않는다. 자동 정리는 VM에서 확인했다(스물둘째 작업).
- **2026-11-19에 한 것**
  - Kali 시험 실행 1(공격만)·실행 2(정상 배경 35분 + 공격, [DD-017](design-decisions/DD-017-lab-background-traffic.md)), 시연 주장 문장 5개 확정([단계 6](stage-6-progress.md) 스물둘째 작업).
  - 결합 v2([DD-018](design-decisions/DD-018-fusion-merge-overlaps.md)), 분석가 검토 결정 경로([DD-019](design-decisions/DD-019-review-decision-path.md), DB 함수 + 파이프라인 재개), 같은 자산 알림 묶음(DD-010 결정 5, Slack 스레드), 분석가 결론 집계 뷰(migration 017).
  - 단계 7: 묶음 버전 2(v1 규칙)·3(v2 규칙) 등록, 교체 → 롤백 → 재교체를 실제 추론으로 확인. **배포 VM champion = 버전 3**([단계 7](stage-7-progress.md)).
  - 포트폴리오: README, 한 장 요약, 문서·스크립트 색인, 공개 저장소 https://github.com/prosild/zeek_AD 첫 커밋. 시험 178개.
- **2026-11-21에 한 것**: 대시보드 모델 표시 이름 확정(기준선 이탈·행위 패턴 이탈·통신 관계 이상, 데이터 계약, Q63, 대시보드 반영은 그쪽 세션), 운영 LLM 요청 모델 gemini-3.8-flash(`report.v2.json`, Q64, 배포 VM 반영), 데이터 출처 인용(README 출처 절), 수집 구간 표시 이름(Q65). 대시보드에 보낼 글 [dashboard-handoff-2026-11-21.md](dashboard-handoff-2026-11-21.md)(사용자가 전달). 시험 181개.
- **2026-11-23에 한 것**: Gemini 요금 상한 초과(429 569건) 원인 확인과 한도 초과 차단기(`zeek_ad/quota.py`, 평가 동결 파일은 그대로), 호출 실패로 끝난 25건 재생성(`live_agent.py --redo-failed-calls`), 배포 VM 반영. 늘어난 사건 재보고는 그대로 둔다(Q70). [단계 7](stage-7-progress.md) 열셋째 작업. 시험 196개.
  - Slack 알림 방식 확인(Q71, 스레드 답글 그대로)과 대시보드의 스레드 열 질문 회신(Q72): 공개 스냅샷 126행은 스레드 규칙 도입 전 기록이라 null이다. 데이터 계약에 읽는 법을 더하고 [2026-11-23 전달 글](dashboard-handoff-2026-11-23.md)을 썼다(사용자가 전달). 열넷째 작업.
- **2026-11-26에 한 것**: 외부 피드백의 파이프라인 쪽 항목 접수(Q73, 순서는 정답 기록·탐지 표 → 브로드캐스트 오탐 → 종결 건 재개 → 인젝션 시험·문구·ATT&CK 후보 수 → 기준선·TGN). 실습망 공격 정답 설정 `configs/ground-truth/lab-attacks.v1.json`(에피소드 11개, 독립 검토 반영). [단계 7](stage-7-progress.md) 열다섯째 작업. 진행 방식은 설계 세션 + 작업자 + 맥락 없는 검토자(Q74).
  - 탐지 여부·걸린 시간 표: [lab-attack-detection.md](lab-attack-detection.md)(판정 기준 Q75, 8종 중 잡힘 4·구분 안 됨 1·후보만 2·놓침 1, 잡힌 것은 첫 알림까지 3.6\~15.2분). 코드 `zeek_ad/lab_truth.py`·`lab_detection.py`, 시험 253개. 열여섯째 작업. README·한 장 요약에 반영했고(7종 → 8종 11회) 대시보드에 보낼 글 [dashboard-handoff-2026-11-26.md](dashboard-handoff-2026-11-26.md)을 썼다(사용자가 전달). 다음 순서는 브로드캐스트 오탐 튜닝이다(예외 규칙 계약 T55를 함께 정함).
  - **배포 VM의 `pipeline`·`collector` 컨테이너는 멈춰 있다.** 유휴 실습망에서도 5분마다 사건이 생겨 LLM 호출이 이어지기 때문이다. 브로드캐스트 오탐 규칙을 배포하기 전에는 켜지 않는다. 켤 때는 `$DC --profile app start collector pipeline`.
  - 브로드캐스트 오탐: 큐 자격 규칙([DD-021](design-decisions/DD-021-queue-eligibility-non-host-only.md), Q76·Q77)을 구현하고 내려받은 자료로 전후를 쟀다(유휴 3일 사건 271 → 0, 공격한 날 88 → 21, 공격 사건은 그대로). 시험 288개. [단계 7](stage-7-progress.md) 열일곱째 작업. **배포 VM에는 아직 올리지 않았다.** 다음은 VM 반영과 확인(DD-021 "배포할 때 알아야 할 것"), 그 뒤 탐지 표 재측정, 예외 규칙 계약(T55), 종결 건 재개(T53).
  - 실습망 캡처의 Zeek 로그와 DB 표는 로컬에 있다(`outputs/live/zeek/lab-*`, `outputs/lab_eval/vm-export-20261126/`). 탐지 표와 오탐 수치는 VM 없이 계산할 수 있다.
  - **끝나면 할 일(사용자 요청, 2026-11-26)**: 포트폴리오·이력서를 만드는 세션이 따로 있다(zeek_AD 세션, 대시보드 세션과 별개). 피드백 작업이 다 끝나면 이미 만든 이력서·포트폴리오에서 고칠 내용을 그 세션에 전달할 수 있게 정리한다. 지금까지 쌓인 것: 실습망 공격 "7종" → 8종(11회), 정성 표(잡음/약하게/놓침) → 판정과 첫 알림까지 걸린 시간(잡힘 4·구분 안 됨 1·후보만 2·놓침 1, 3.6\~15.2분), 느린 유출 "약하게" → "후보만", 시험 수 196 → 288, 설계 결정 20 → 21건, 브로드캐스트 오탐 튜닝(유휴 3일 사건 271 → 0, 공격한 날 88 → 21. 배포 VM 확인 전), "실제 공격" → "모사한 공격"(PR #1의 표현).
- **Java 대시보드 쪽(그쪽 AI 보고를 사용자가 전달, 2026-11-18)**: T01\~T05 완료. 데이터 계약 v2.1과 VMware 단일 Compose를 반영했다. Compose에 붙일 때 근거 API는 `http://api:8000`, DB는 `postgres:5432`. TLS 인증서는 배포 VM NAT 주소(SAN). 이 폴더와 대시보드 폴더는 파일을 주고받지 않는다(방법은 미정).
- 끝난 단계: 단계 3(기준선·IF·Transformer·TGN·합성 APT·결합 DD-009), 단계 4(DB·MLflow 등록·worker·근거 API·대시보드 뷰), 단계 5(5a RAG, 5b LLM 보고서·판단 모델·Slack dry-run·LangGraph), 단계 6(파일 단위 파이프라인 DD-012, VMware 배포 DD-015, 실습망 시험), 단계 7(모델 교체·롤백).
- 사용자 실습: 노트북 01\~04 완료(2026-11-10), LangGraph 실습 05(실습 노트북, 저장소에 없음)(2026-11-18).

## 남은 일 (순서대로)
1. ~~Kali 공격 시나리오와 결과 해석~~ 끝(스물둘째 작업, 주장 문장 확정). 남은 확인: 알림 묶음의 실제 Slack 기록은 다음 실습망 트래픽 때 본다.
2. ~~분석가 검토 결정 경로(Q50 2번)~~ 끝(DD-019, DB 함수 `dashboard.decide_review` + 파이프라인 재개, 스물넷째 작업). 같은 자산 알림 묶음(DD-010 결정 5)도 끝(스물다섯째 작업, Slack 스레드·30분 재알림, VM 실제 기록은 다음 트래픽 때 확인).
3. 대시보드: Compose에 붙이기(대시보드 쪽 AI가 한다). 그쪽에 알릴 것: Slack 기록은 보고서 작업이 아니라 `incident_id`로 찾는다(DD-016), 검토 결정은 `dashboard.decide_review`(DD-019), 사건 창은 결합 v2부터 모델 창의 합(DD-018), Slack 기록의 스레드 열 `zeekad_thread_parent`·`zeekad_reply_broadcast`(DD-010 결정 5). 모두 [데이터 계약 v2](data-contract-v2.md)에 있다.
4. ~~단계 7: 모델 교체·롤백 시연~~ 끝([단계 7 진행 기록](stage-7-progress.md)). 배포 VM champion = `zeekad-fusion` 버전 3(결합 v2). 버전 2는 같은 코드의 v1 규칙(롤백 대상). 대시보드 AI에게 보낼 글: [dashboard-handoff-2026-11-19.md](dashboard-handoff-2026-11-19.md)(사용자가 전달).
5. 포트폴리오 문서(2026-11-19 진행 중, 사용자가 다른 세션에서 이어 간다)
   - [README.md](../README.md): 사용자와 1차 검토 반영(2026-11-19, [단계 7](stage-7-progress.md) 셋째 작업). 커밋 전.
   - [portfolio-summary.md](portfolio-summary.md): 한 장 요약(Markdown으로 두기로 사용자 결정). README에 맞춤(2026-11-19, 단계 7 셋째 작업). 커밋 전.
   - git: 2026-11-19 첫 커밋(`8a85ee3`)을 공개 저장소 https://github.com/prosild/zeek_AD 에 올렸다(파일 260개, 4.0MB). 작성자는 GitHub noreply 주소(이 저장소 로컬 설정), 올리기는 `gh` 로그인(HTTPS). 공개하지 않는 것: `CLAUDE.md`·`AGENTS.md`, 강의 정리 문서 2개, `historical/`, 실습 노트북, `outputs/`, `data/`, `deploy/.env`(원격에 없음 확인). 색인 [docs/README.md](README.md)·[scripts/README.md](../scripts/README.md).
   - 사용자 GitHub: https://github.com/prosild . Java 대시보드 저장소 https://github.com/prosild/zeek_ad_dashboard (README·docs/README·한 장 요약에 링크함).
   - 데모(스크린샷·영상)는 남았다. EDA 정리는 [eda-design-evidence.md](eda-design-evidence.md)(그림 `docs/figures/eda/`, 원본 `outputs/eda/`).
- 미룬 것: zeek-ad 환경의 pandas 3.1.0 ↔ 잠금 파일 2.3.3 정리(Q52 5번), 대시보드와 파일을 주고받는 방법.

## 자주 쓰는 명령
- 시험: `python -m unittest discover -s tests`(zeek-ad 환경, 프로젝트 루트).
- 이 PC: `docker compose -f deploy/compose.yaml --env-file deploy/.env up -d` → `python scripts/db_migrate.py`. 근거 API `python scripts/run_api.py`(http://127.0.0.1:8000/docs), MLflow 화면 `python scripts/mlflow_ui.py`(http://127.0.0.1:5000).
- 배포 VM(ssh `zeekad-vm`, `~/zeek_AD`): `DC="docker compose -f deploy/compose.yaml --env-file deploy/.env"`, `$DC --profile app ps`, 로그 `$DC --profile app logs pipeline`, 에이전트 손으로 `$DC --profile app exec -T pipeline python scripts/live_agent.py --capture lab-YYYYMMDD`.

## 지켜야 할 방향 (자주 틀리는 것)
- 목적은 ML·DL 모델이다. 룰 기반 곁가지 탐지기(first-seen, fan-out, beaconing), Suricata 기준선, 위험 누적을 추가하지 않는다. 외부 리뷰가 권해도 마찬가지다.
- CIC가 오래된 알려진 공격 데이터라는 점은 전제다. 학습/평가 분리를 "보지 못한 공격" 가정으로 둔다.
- TGN은 사용자 설계(DD-007)다. KAIROS 등 논문은 수준 참고일 뿐, 논문 설계로 바꾸지 않는다. 우려는 해결할 설계 과제로 다룬다.
- 실습 노트북은 실무 API(Dataset/DataLoader, nn.Embedding, nn.TransformerEncoder, PyG, MLflow) 수준으로, 셀마다 "코드 | 뜻" 표를 둔다.
- 검증은 Claude가 직접 실행하고 보고한다. 사용자에게 같은 실행을 반복시키지 않는다.
- 평가 보류(월요일 holdout)는 임계값용이라 epoch 선택에 쓰지 않는다. 정답 선택 조건은 평가 전용이다.
- 알려진 기록 흠: 단계 3a의 metrics.json 일부는 불리언이 문자열로 저장돼 있다(값은 맞음). `outputs/diagnostics/long_connections.json`은 마지막 실행 모델만 담는다.
