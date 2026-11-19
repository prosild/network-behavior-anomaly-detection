# 단계 3 진행 기록

시작일: 2026-11-05. 기준은 [최종 설계](../FINAL_PROJECT_DESIGN.md) 5·6·8절과 [DD-005](design-decisions/DD-005-deadline-scope.md) 일정이다.

## 첫 작업: 정답 에피소드(V4)

- 결과와 근거: [ground-truth-v1.md](ground-truth-v1.md). confirmed 16, uncertain 1.
- 점수를 보기 전에 동결했다.
- 공통 도우미 [zeek_ad/provenance.py](../zeek_ad/provenance.py)를 새로 만들었다.
  - 내용: 파일 해시·경로 기록.
  - 새 스크립트부터 쓴다. 기존 Silver·Gold 스크립트는 manifest에 기록된 코드 해시가 바뀌지 않도록 그대로 둔다.

## 두 번째 작업: 평가기

- [zeek_ad/evaluation.py](../zeek_ad/evaluation.py): 설계 5.2·5.3절. 표준 라이브러리만 쓴다.
  - 임계값: 보류 구간 점수의 p95(선형 보간). 동률은 후보에 넣는다.
  - 사건 만들기: 같은 자산·역할의 연속 창을 병합한다. 첫 창부터 30분까지 한 사건이다.
  - 큐 순서: 점수 내림차순, 동점은 고정 해시(`zeek-ad-tie-v1`) 오름차순.
  - 지표: 최대 일대일 대응(증가 경로)으로 Recall@N. 보조 지표는 공격 포함 Recall@N.
  - 공격별 결과: 대응 사건 수, 추가 사건 수, 예산 점유율.
  - 경계 동점 민감도: seed 42, 1,000회.
- [tests/test_evaluation.py](../tests/test_evaluation.py): 가짜 예제로 규칙을 확인하는 테스트 12개. 전체 34개 통과.

## 세 번째 작업: 통계 기준선·Isolation Forest·MLflow

- [zeek_ad/baselines.py](../zeek_ad/baselines.py)
  - 전처리: log1p와 학습 중앙값 대치. 비율 특징은 변환하지 않는다.
  - 양쪽 꼬리 희귀도 기준선: 역할을 합친 경험분포에서 계산하고, 특징 중 최댓값을 창 점수로 쓴다.
  - Isolation Forest: 200 trees, `max_samples=256`, seed 42. 역할을 one-hot으로 넣는다.
- [scripts/run_baselines.py](../scripts/run_baselines.py): 월요일 train 958+328창으로 적합하고 화~금을 평가한다. 결과는 두 곳에 남긴다.
  - `outputs/eval/<시각>-<모델>/`
  - MLflow(`outputs/mlflow/mlflow.db`, 실험 `zeek-ad-stage3`). 입력·코드는 해시로 연결한다.
- 미탐 원인 진단: 에피소드마다 후보 생성 실패(임계값 미달)와 순위 손실을 구분한다.

### 첫 결과(Claude, 2026-11-05)

Recall@10(일대일, 고정 해시 순서):

| 날 | 분모 | 꼬리 희귀도 | IF |
| --- | ---: | ---: | ---: |
| 화 | 2 | 0 | 0 |
| 수 | 5 | 4 | 0 |
| 목 | 6 | 2 | 0 |
| 금 | 3 | 2 | 0 |

- **꼬리 희귀도:**
  - 학습 범위를 벗어난 값이 모두 최대 희귀도 log(1287)=7.16을 받는다. 그래서 상위가 동점으로 가득 찬다.
  - Recall@10의 동점 민감도 평균(최소~최대)은 목 0.21(0.17~0.33), 금 0.77(0.33~1.0), 수 0.70(0.6~0.8)이다. **고정 해시 결과는 순서 선택에 크게 기댄다.**
  - 미탐: 화요일 Patator 2건과 목요일 웹 공격 3건. 모두 임계값에 닿지 않았다(후보 생성 실패).
- **IF:**
  - 대부분의 공격 창이 후보는 됐다. 하지만 순위가 12~76위라 상위 10에 들지 못했다(순위 손실).
  - 상위 10은 워크스테이션의 responder 창이 채운다. 월요일 학습에 드문 유형이다.
  - Recall@50에서는 수 5/5, 금 3/3이다.
- uncertain 014는 어느 모델의 상위 10에도 걸리지 않았다.
- 설계 6.2절에 따라 이 결과를 보고 설정을 바꾸지 않는다. 변경은 사전 정의한 비교 예산 안에서만 한다.

## 학습 계획 조정(2026-11-05, 사용자 요청)

- **Isolation Forest:** 직접 구현하지 않는다. 원리와 결과 해석을 설명할 수 있게 한다.
- **MLflow:** 사용자가 처음 배운다. practice/02_mlflow_basics.ipynb(실습 노트북, 저장소에 없음)를 만들었다.
  - 다루는 범위: Tracking, 모델 저장·불러오기, skops 형식, Registry alias 배포·롤백, 프로젝트 기록 조회.
  - Claude가 코드 셀을 순서대로 실행해 오류가 없는 것을 확인했다.
  - 작성 중 MLflow 3.17에서 확인한 두 가지:
    - sklearn 모델은 pickle 대신 skops로 저장한다. 트리 타입은 `skops_trusted_types`로 신뢰를 명시해야 한다.
    - pyfunc의 `predict`는 IF의 -1/1 판정이다. 점수가 필요하면 custom pyfunc가 필요하다(단계 4).
- **Transformer(단계 3b):** 사용자가 PyTorch로 직접 구현한다. Claude는 데이터 준비·평가 연결과 단계별 안내를 맡는다.

## 네 번째 작업: NAT 편향 진단과 긴 연결 진단(V5)

### NAT 편향 진단
- [scripts/build_nat_diagnostic.py](../scripts/build_nat_diagnostic.py): 창마다 상대가 172.16.0.1인 연결 수. 배포하지 않는다.
  - 주소를 알게 된 경위: 데이터셋 설명(공격망 NAT)과 단계 0의 사전 탐색.
- 평가: [run_baselines.py](../scripts/run_baselines.py)에 `nat_presence`(유무 0/1)와 `nat_count`(연결 수)를 같은 평가 규약으로 넣었다.
  - 월요일에는 NAT 연결이 있는 창이 1개뿐이다. 그래서 보류 p95가 0이 되어 모든 창이 후보가 된다.
  - 그래서 후보 규칙만 "NAT 연결 ≥ 1"로 바꿨다. 사건 생성·순위·Recall 계산은 같다.

Recall@10(고정 해시 순서), 화·수·목·금:

| 점수 | 화 | 수 | 목 | 금 | 합 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 꼬리 희귀도 | 0/2 | 4/5 | 2/6 | 2/3 | 8/16 |
| IF | 0/2 | 0/5 | 0/6 | 0/3 | 0/16 |
| NAT 유무 | 2/2 | 3/5 | 3/6 | 1/3 | 9/16 |
| NAT 연결 수 | 2/2 | 4/5 | 4/6 | 2/3 | 12/16 |

- **주소 하나를 아는 것만으로 두 모델보다 많이 맞힌다.** CIC 평가 결과의 상당 부분이 "공격이 NAT 주소에서 온다"는 데이터셋 특성으로 설명된다. 모델 성능을 말할 때 이 진단을 함께 공개한다.
- **NAT로 못 찾는 것:** Botnet(015)과 MAC(013)은 NAT 연결이 없다(내부 출발, C2는 외부 주소). 꼬리 희귀도는 Botnet을 2위로 찾았다. 주소 지식으로 설명되지 않는 행동 기반 탐지의 몫이다.
- NAT 유무는 동점이 많다. 동점 민감도 평균은 수 0.58, 목 0.54, 금 0.48이다.

### 긴 연결 진단(설계 4.3절)
- [scripts/diagnose_long_connections.py](../scripts/diagnose_long_connections.py): 월요일 보류 312창 기준.
- 300초 초과 연결이 바이트의 절반 이상인 창은 전체 보류 창의 2.6%다.
- 그런 창이 상위 N에서 차지하는 비율:
  - 꼬리 희귀도: 상위 10의 10%(1창, .50 originator, 894초 연결), 상위 20의 5%.
  - IF: 상위 10·20 모두 0%.
- 결론: v1 특징에서는 긴 연결이 상위 순위를 차지하지 않는다. 특징 해석을 바꿀 근거가 없다.
- 결과 파일: `outputs/diagnostics/long_connections.json`.

단계 3a 완료. 남은 V5 항목은 없다. `-C` 비교는 DD-005에서 미뤘다.

## 다섯 번째 작업: 단계 3b 입력 고정과 시퀀스 데이터(2026-11-05)

### 평가 전에 고정한 값
[configs/models/transformer.v1.json](../configs/models/transformer.v1.json). 화~금 결과를 보기 전에 정했다. 바꾸려면 v2로 만들고 이유를 기록한다.
- K=12(직전 1시간). 다른 캡처의 창은 맥락에 넣지 않는다.
- 토큰 21차원 = 표준화 특징 18 + `role_responder` + `is_inactive` + `is_outside`.
  - 활동 없음(DD-002가 구현 전 확정을 요구한 규칙): 캡처 안이지만 Gold 행이 없는 칸. 특징 0(학습 평균), `is_inactive=1`.
  - 캡처 밖: 캡처 첫 칸보다 앞선 칸. 특징 0, `is_outside=1`. 마스크 대신 표시를 써서 캡처 첫 창도 점수를 받는다(전부 마스크하면 attention이 NaN이 된다).
- 대상은 Gold 행이 있는 창만이다. 학습 대상은 월요일 train 1,286행이다.
- 전처리: IF와 같은 `Preprocessor`(train 적합) 뒤에 train 평균·표준편차 표준화.
- 모델: d_model 32, head 4, 2층, feed-forward 64, dropout 0.1, 학습 위치 임베딩, 마지막 칸 → Linear(32, 18). parameter 18,770개.
- 학습: MSE, Adam lr 0.001, batch 64, 100 epoch 고정, seed 42, CPU. 점수는 18개 특징의 평균 제곱 오차.

### 시퀀스 데이터
- [zeek_ad/sequences.py](../zeek_ad/sequences.py), [scripts/build_sequences.py](../scripts/build_sequences.py) → `outputs/sequences/transformer_v1/`(x 8277×12×21, y 8277×18, index, manifest).
- 검증: [tests/test_sequences.py](../tests/test_sequences.py) 4개 통과(활동 없음·캡처 밖·계열 분리·상수 특징). 빌드 검사(NaN 없음, train 대상 평균 0, 칸마다 표시 하나 이하) 통과.
  무작위 300행의 맥락 토큰을 index로 다시 찾아 대조했고 불일치 0이다.
- 표시 비율: train 맥락 칸의 2.2%가 활동 없음, 7.1%가 캡처 밖이다.

### 실습 노트북
- practice/03_transformer_pytorch.ipynb(실습 노트북, 저장소에 없음): 실무 API 수준이다. 사용자가 빈칸 4개를 채운다.
  - 처음 판(attention 수식·tensor 기초부터)은 사용자가 "너무 저차원"이라고 해서 바꿨다. 사용자는 `nn.Embedding`·`nn.TransformerEncoder` 같은 표준 모듈로 실제 데이터를 학습하는 연습을 원했다.
  - 빈칸: `Dataset`, 모델(`nn.Linear`+`nn.Embedding` 위치+`nn.TransformerEncoder`), `train_one_epoch`/`evaluate_loss`, `predict_scores`.
  - 주어진 코드: DataLoader(학습 섞기, 평가·추론 순서 유지), 실습용 MLflow 기록(param, step metric, artifact), `state_dict` 체크포인트 저장·`weights_only=True` 불러오기.
- 정답 예시: practice/solutions/03_transformer_solution.py(실습 노트북, 저장소에 없음).
- Claude가 정답을 채운 상태로 전체를 두 번 실행했다. 결과가 같았다(CPU 15초).
  - 학습 loss 1.0 → 0.24. 보류 loss 0.70 → 최저 0.41(28 epoch) → 0.47. 과적합이 보인다.
  - 고정 규칙대로 100 epoch를 쓴다. 보류는 임계값용이라 epoch 선택에 쓰면 임계값이 낮게 오염된다.
  - 보류 p95 1.692. 체크포인트를 다시 불러온 점수가 학습 직후와 완전히 같다. 화~금 평가는 아직 하지 않았다.

## 여섯 번째 작업: Transformer 공식 실행과 평가(2026-11-06)

### 코드
- [zeek_ad/transformer_model.py](../zeek_ad/transformer_model.py): 사용자가 노트북에서 작성한 `WindowSequences`, `WindowTransformer`, `train_one_epoch`, `evaluate_loss`를 그대로 옮겼다(사용자 요청으로 Claude가 옮김).
  - 저장된 노트북의 `predict_scores`는 미완성이라 노트북 명세대로 채웠다. `build_model`을 추가했다.
- [zeek_ad/experiment.py](../zeek_ad/experiment.py): `run_baselines.py`의 평가·MLflow 공통 부분을 옮겼다. 두 스크립트가 같은 평가기를 쓴다.
  - 옮긴 뒤 단계 3a의 점수 4개를 다시 평가해 기존 metrics.json과 완전히 같음을 확인했다.
  - 단계 3a run의 lineage 코드 해시는 옮기기 전 `run_baselines.py`를 가리킨다. 평가 결과는 같다.
  - 고친 것: 진단의 `candidate`·`max_window_score`가 numpy 값이라 metrics.json에 문자열(`"False"`)로 남았다. 파이썬 bool·float로 바꿨다. 단계 3a 파일에는 문자열로 남아 있다(값은 맞다).
- [scripts/run_transformer.py](../scripts/run_transformer.py): 입력 해시 확인(설정·Gold·시퀀스) → 고정 설정 학습(CPU) → 점수 → 보류 p95 → 같은 평가기 → `outputs/eval/20261106T034305Z-transformer/` + MLflow(stage 3b, epoch별 loss, lineage, 체크포인트).
  - 첫 실행 두 번은 JSON 직렬화 문제(float32 임계값, numpy bool)로 지우고 다시 돌렸다. 학습·점수는 결정적이라 세 번 모두 같았다.
  - 노트북 결과와 같다: 보류 loss 최저 0.405(28 epoch), 마지막 0.471, 임계값 1.692.

### 결과: Recall@10(고정 해시 순서), 화·수·목·금

| 점수 | 화 | 수 | 목 | 금 | 합 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 꼬리 희귀도 | 0/2 | 4/5 | 2/6 | 2/3 | 8/16 |
| IF | 0/2 | 0/5 | 0/6 | 0/3 | 0/16 |
| **Transformer** | 0/2 | 4/5 | 2/6 | 2/3 | **8/16** |
| NAT 연결 수(진단) | 2/2 | 4/5 | 4/6 | 2/3 | 12/16 |

- Transformer는 경계 동점이 없다(연속 점수). 꼬리 희귀도의 8/16은 동점 순서에 따라 흔들리지만 Transformer의 8/16은 고정이다.
- 수요일 DoS 5개가 모두 상위 10에 들지만 Hulk(005)와 GoldenEye(006)가 같은 사건(6위) 하나에 겹쳐 일대일 대응은 4개다.
- 공격별 최고 순위(— = 후보 아님):

| 에피소드 | 꼬리 | IF | Transformer | NAT |
| --- | ---: | ---: | ---: | ---: |
| 001 FTP-Patator | — | 75 | — | 1 |
| 002 SSH-Patator | — | 60 | — | 4 |
| 003~006 DoS | 4·2·2·1 | 14·14·14·19 | 10·7·6·6 | 2·2·1·1 |
| 007 Heartbleed | 10 | 13 | **1** | 15 |
| 008~010 Web | —·—·— | 76·75·— | 54·54·62 | 2·3·3 |
| 011 Infiltration 스캔 | 7 | 18 | 7 | 1 |
| 012 Infiltration Vista | 1 | 12 | 1 | 9 |
| 013 MAC | 51 | 57 | — | — |
| 015 Botnet | 2 | 27 | 3 | — |
| 016 PortScan | 6 | 17 | 1 | 1 |
| 017 DDoS | 19 | 41 | 51 | 2 |

- 해석:
  - Transformer는 웹 공격 3개를 후보로 만든 유일한 행동 모델이다(순위는 54~62위).
  - Patator 2개는 세 모델 모두 놓친다(후보 생성 실패). Botnet은 NAT로 못 찾지만 Transformer 3위, 꼬리 2위.
  - IF와 같은 전처리를 쓰는데 결과가 크게 다르다. 차이는 모델 구조(직전 1시간 맥락)와 점수 정의(예측 오차)에서 온다.
- 긴 연결 진단: 보류 상위 10에 긴 연결 지배 창 0%, 상위 20에 5%(1창). 문제 없음.
- 미확정 에피소드(014)는 상위 10에 닿지 않았다.
- 모델 등록: 설계 8절의 배포 단위(모델+전처리+임계값 묶음)로 단계 4에서 IF와 함께 등록한다. 지금은 체크포인트를 run artifact로 남겼다.

### 사용자 결정 대기: DD-002 3절의 합집합 사건 생성
DD-002는 "Transformer가 IF가 놓친 confirmed 에피소드를 찾으면 두 모델 후보의 합집합 사건 생성을 검토한다"고 정했다. 조건이 충족됐다(IF 0/16, Transformer 8/16).
설계 6.2절에 따라 기본 모델(IF)은 평가 결과를 보고 바꾸지 않는다. 합집합을 하면 결합 순위 규칙을 먼저 정하고 새 버전으로 따로 평가하며, 같은 평가셋 재사용을 공개한다.

## 일곱 번째 작업: DD-006 작업 1, 자명한 기준선 B와 신뢰구간(2026-11-06)

[DD-006](design-decisions/DD-006-behavior-detectors-reduced.md)의 축소안 첫 단계다. **결과 노출 이후의 설계 변경이다.**

### 코드
- [configs/detectors/new-external-peers.v1.json](../configs/detectors/new-external-peers.v1.json): 평가 전에 고정했다.
  - seen-set: 월요일 train 창의 외부 상대 IP.
  - 점수: 창의 처음 보는 외부 상대 수. 평가 중 갱신하지 않는다.
  - 임계값: max(보류 p95, 1).
- [scripts/build_new_peer_baseline.py](../scripts/build_new_peer_baseline.py) → `outputs/diagnostics/new_external_peers_v1/`.
  - seen 외부 IP 8,614개(전체 19,048개).
  - 검사: 월요일 train 창 점수 합 0, Gold에 없는 점수 행 0. 172.16.0.1은 월요일 train(12:35 UTC)에 한 번 나와 seen-set에 들어 있다. 그래서 이 기준선은 NAT 주소를 새 IP로 세지 않는다.
- [zeek_ad/evaluation.py](../zeek_ad/evaluation.py): `pooled_hits`(하루별 일대일 대응 → 에피소드별 0/1), `bootstrap_recall_ci`. 테스트 3개를 추가해 `tests.test_evaluation` 15개가 통과한다.
- [scripts/run_detector.py](../scripts/run_detector.py): 설정 파일 하나로 탐지기 점수를 기존 평가기로 평가한다. 설정·점수·Gold 해시를 확인하고, 신뢰구간을 저장한다. MLflow stage 태그는 3c다. 저장소가 git이 아니라서 커밋 해시 대신 lineage에 SHA-256을 남긴다.
- [scripts/summarize_eval.py](../scripts/summarize_eval.py): 모델별 최신 run을 모아 표를 만든다 → `outputs/eval/_summary/`.

### 결과 (기준선 B: 임계값 22)
| 모델 | 화@10 | 수@10 | 목@10 | 금@10 | 합계@10 [95% 구간] | 합계@50 [95% 구간] |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| NAT 유무(A) | 2/2 | 3/5 | 3/6 | 1/3 | 9/16 [0.31, 0.81] | 13/16 [0.62, 1.00] |
| NAT 연결 수(A') | 2/2 | 4/5 | 4/6 | 2/3 | 12/16 [0.56, 0.94] | 13/16 [0.62, 1.00] |
| 처음 보는 외부 상대 수(B) | 0/2 | 0/5 | 0/6 | 1/3 | 1/16 [0.00, 0.19] | 2/16 [0.00, 0.31] |
| 꼬리 희귀도 | 0/2 | 4/5 | 2/6 | 2/3 | 8/16 [0.25, 0.75] | 9/16 [0.31, 0.81] |
| IF | 0/2 | 0/5 | 0/6 | 0/3 | 0/16 [0.00, 0.00] | 10/16 [0.38, 0.88] |
| Transformer | 0/2 | 4/5 | 2/6 | 2/3 | 8/16 [0.25, 0.75] | 9/16 [0.31, 0.81] |

- 구간: 에피소드 16건을 복원 추출하는 bootstrap(1,000회, seed 42) 백분위수 방식. 같은 날 공격끼리의 의존성은 반영하지 않는 근사다.
- 기준선 B는 Botnet(015)을 금요일 1위로 찾는다(새 외부 IP 95개). NAT로 못 찾는 사건이다. 목요일 Infiltration Vista(012)는 후보지만 15위다. 나머지 NAT 출발 공격은 점수 0이다(172.16.0.1이 seen이기 때문).
- 꼬리 희귀도·Transformer(8/16)와 NAT 연결 수(12/16)의 구간이 겹친다. 16건으로는 이 차이를 확실하다고 말할 수 없다.
- 기존 4개 run은 다시 평가하지 않았다. 저장된 matching만 읽었고, 숫자가 단계 3a·3b 표와 같다.

## 여덟 번째 작업: DD-006 작업 2-1, first-seen 탐지기(2026-11-06)

### 코드
- [zeek_ad/first_seen.py](../zeek_ad/first_seen.py): 규칙(표준 라이브러리). [tests/test_first_seen.py](../tests/test_first_seen.py) 8개 통과.
  - 항목: 외부는 (방향, 자산, /24), 내부는 (출발, 도착, 프로토콜:포트군).
  - 가중치: 외부 1, 내부 쌍 3, 내부 원격 관리(ssh·rpc·smb·rdp·winrm) 10.
  - 갱신: 경보 없던 창의 새 항목만 12창(1시간) 뒤에 편입한다. 같은 항목이 어느 행에서든 경보면 편입하지 않는다. 화→금으로 이어 간다.
- [configs/detectors/first-seen.v1.json](../configs/detectors/first-seen.v1.json), [first-seen-no-nat.v1.json](../configs/detectors/first-seen-no-nat.v1.json)(172.16.0.0/24 제외 진단): 평가 전에 고정했다.
- [scripts/build_first_seen.py](../scripts/build_first_seen.py): Spark로 역할 행을 줄인 뒤 pandas에서 채점한다.
  - 월요일 train seen 항목은 11,930개다. 금요일 끝에는 30,854개가 된다.
  - 임계값(보류 p95)은 36.45다. 월요일 train 창의 점수는 모두 0이다.
- `run_detector.py`에 점수 생성 때 쓴 임계값과 평가 임계값이 같은지 확인하는 검사를 추가했다.

### 결과
| 모델 | 화@10 | 수@10 | 목@10 | 금@10 | 합계@10 [95% 구간] | 합계@50 [95% 구간] |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| first-seen | 0/2 | 0/5 | 1/6 | 1/3 | 2/16 [0.00, 0.31] | 3/16 [0.00, 0.38] |
| first-seen(NAT 제외) | 0/2 | 0/5 | 1/6 | 1/3 | 2/16 [0.00, 0.31] | 3/16 [0.00, 0.38] |

- 잡은 것: Infiltration Vista(012) 목 1위(새 내부 항목 1,360개, 점수 4,341), Botnet(015) 금 1위(새 외부 대역 109개). 둘 다 **내부 출발 행동**이고 NAT 진단으로는 못 찾는 유형이다.
- NAT 제외판과 결과가 같다. 이 탐지기는 NAT 주소 지식에 기대지 않는다.
- 못 잡은 것: 172.16.0.1에서 들어오는 공격 대부분. 원인은 설계상 약점이다(결과를 보고 알게 됨).
  - 외부 항목은 (방향, 자산, /24) 하나라서, 공격 첫 창의 점수가 1(외부 가중치)뿐이다. 임계값 36에 못 미친다.
  - 그래서 "경보 없는 항목"으로 1시간 뒤 seen-set에 들어간다. 이후 같은 /24의 공격(수요일 DoS 등)은 0점이 된다.
  - v1은 결과 노출 이후 바꾸지 않는다. 한계와 후속 개선 후보(외부 inbound 가중치, 편입 조건에 연속 관측 요구)로 기록한다.
- MAC(013)은 새 외부 대역 28개로 점수 28이다. 임계값 36.45 아래라 후보가 되지 못했다.

## 아홉 번째 작업: DD-007 TGN 1단계, Zeek run.v2와 이벤트 표(2026-11-06)

방향 전환: 행동 탐지기 확장을 중단하고, 사용자 설계의 TGN 이벤트 그래프 모델로 간다([DD-006 수정 절](design-decisions/DD-006-behavior-detectors-reduced.md), [DD-007](design-decisions/DD-007-tgn-event-graph.md)).

### Zeek run.v2
- [configs/zeek/run.v2.json](../configs/zeek/run.v2.json) = v1 + [tgn-extras.zeek](../configs/zeek/tgn-extras.zeek)(community_id, FTP USER/PASS 기록) → `outputs/zeek/<요일>/run-02`. run-01은 그대로다.
- 검사:
  - conn 행 수는 다섯 날 모두 run-01과 같다.
  - Silver uid가 run-02 conn에 모두 있다(누락 0).
  - ftp.log는 화요일 1,086행에서 29,811행이 됐다. 로그인 시도가 보인다.

### 이벤트 표
- [scripts/build_tgn_events.py](../scripts/build_tgn_events.py) → `outputs/events/tgn_v1/`.
  - Silver conn 한 행이 이벤트 하나다(전체 2,119,277).
  - uid별 요약을 붙였다: dns, http, ssl, ssh, ftp, smb_mapping·smb_files, kerberos, dce_rpc, ntlm. 열은 66개다.
  - 기존 창 라벨(split)도 붙였다.
- 값은 원래 값이다. 인코딩은 학습 단계에서 월요일 train으로만 적합한다.
- 검사:
  - 이벤트 수가 Silver와 같고, uid 중복은 0, split 결측은 0이다.
  - 알려진 uid 하나를 원본 http.log와 대조했다(GET www.msftncsi.com, 200, URI 길이 9). 일치한다.
- 월요일 이벤트: train 302,400, holdout 66,713, 경계 3,720, 양끝 2,599.
- 참고: `ftp_fail_n`은 모든 명령의 530 응답 수다. USER 단계의 530도 포함한다.
- 결과 노출: run-02 확인 중 화요일 ftp.log의 172.16.0.1 행 두 개를 봤다.

## 열 번째 작업: DD-007 TGN 2단계, 시간 그래프 데이터(2026-11-06)
- [configs/models/tgn.v1.json](../configs/models/tgn.v1.json)의 data 절을 고정했다. 어휘 min_count 2, history 12자, IP 해시 16차원, DNS 손실 가중치 0.2.
- [zeek_ad/tgn_data.py](../zeek_ad/tgn_data.py)에 인코딩 규칙을 두었다. [tests/test_tgn_data.py](../tests/test_tgn_data.py) 6개가 통과한다.
- [scripts/build_tgn_dataset.py](../scripts/build_tgn_dataset.py) → `outputs/graphs/tgn_v1/`(events.npz, index.parquet, nodes.parquet, encoding.json). 27초 걸린다.
  - 이벤트 2,119,277(train 302,400). 노드 19,093(내부 15, 점수 대상 14). 엣지 정보는 범주 15 + history 12자 + 수치 27이다. 노드 특징은 20차원이다.
  - 검사: 시각이 단조 증가한다. train 수치 평균의 절댓값 최대가 1e-4다. 알려진 uid 하나를 되돌려 원래 값과 같음을 확인했다(포트군, 서비스, 상태, HTTP, 바이트 97, URI 길이 9, history).
  - train이 아닌 이벤트의 "모름" 비율은 port_group 1.8%, ssh_auth 0.16%, 나머지는 0.1% 미만이다.
  - 월요일 train에는 SSH 인증 실패가 2건 미만이다. 그래서 `fail`은 어휘에 없고 "모름"으로 들어간다("값 없음", `ok`와는 구분된다).
- train의 DNS 비중은 59%다.

## 열한 번째 작업: DD-007 TGN 3단계 준비, 설정 고정과 실습 노트북(2026-11-06)

### 설정 고정([configs/models/tgn.v1.json](../configs/models/tgn.v1.json))
TGN 학습과 화~금 평가 전에 model·training·score 절을 채웠다.
- 모델: 엣지 모듈(범주 Embedding 4 × 15 + history Embedding 4 × 12 + 수치 Linear 16 → concat → 32), 메모리 64, 시간 16, 집계 last, 임베딩 TransformerConv(64, head 2, 이웃 10, 노드 특징 Linear 20→64를 메모리에 더함), 디코더 concat(z_출발, z_도착) → 128 → 범주·history·수치 head. parameter 161,200개.
- 학습: 월요일 train 이벤트, batch 200, 10 epoch, Adam lr 1e-3, seed 42, CPU. epoch마다 메모리·이웃을 비운다. 손실 = 범주 CE 평균 + history CE 평균 + 수치 MSE 평균, DNS 가중 0.2.
  - lr은 1e-4와 1e-3을 8 epoch씩 돌려 **train 손실만** 비교해 골랐다. 보류·화~금은 보지 않았다.
- 점수:
  - 캡처(하루)마다 메모리·이웃을 비우고 시간순으로 흘린다. 하루 안에서는 갱신한다. batch마다 점수를 먼저 매기고 갱신한다.
  - 주 점수 recon(이벤트 손실, 가중치 없음), 보조 점수 latent_shift(갱신 전후 메모리 L2). 둘을 결합하지 않고 따로 평가한다. 결합은 ML·DL 결합 결정에서 정한다.
  - 창 집계는 최댓값. 진단: NAT 제외 점수, 공격 구간의 점수 변화.
  - 하루마다 메모리를 비우는 이유: 학습이 빈 메모리에서 시작하므로 같은 조건이 된다. 날 사이 16시간 넘는 공백은 학습 때 본 적 없는 시간 간격이다.

### data 절 수정: 수치 표준편차 하한
- 문제(월요일 train 분포에서 발견): NTLM·SMB·HTTP 오류 같은 희소 특징은 train 표준편차가 0.005~0.05다. 한 번만 나와도 표준화 값이 최대 158이 되어 복원 손실(MSE)을 지배했다. 첫 시험 학습에서 보류 창 recon p95가 290이었다.
- 수정: `numeric_std_floor = 1.0`(log1p 척도). 표준편차가 1보다 작으면 1로 나눈다. 0인 특징도 이 규칙으로 처리된다.
- 데이터를 다시 만들었다(`outputs/graphs/tgn_v1/`). 수치 열 외 배열(src, dst, t, cat, hist, dns_weight, node_x)은 이전과 완전히 같다. 수치 절댓값 최대는 158 → 14다.
- 화~금 결과를 보기 전, 학습 결과도 없는 상태의 수정이라 버전은 v1을 유지하고 설정에 날짜와 이유를 적었다.

### 실습 노트북
- practice/04_tgn_pytorch.ipynb(실습 노트북, 저장소에 없음): 빈칸 5개(1. EdgeEncoder, 2. GraphEmbedding, 3. EdgeDecoder, 4. event_loss·weighted_mean, 5. latent_shift). 각 빈칸 뒤에 확인 셀(shape, parameter 수, 손으로 계산한 값)이 있다.
- 주어진 코드: TemporalData, TemporalDataLoader, TGNMemory·LastNeighborLoader 조립, 메시지 함수, 한 batch 계산, 학습 + MLflow(실습용 `outputs/practice/tgn`), 월요일 점수 흐름, 창 집계.
- 정답 예시: practice/solutions/04_tgn_solution.py(실습 노트북, 저장소에 없음).
- Claude가 정답을 채워 전체를 두 번 실행했다. 결과가 같았다.
  - 학습: epoch당 약 24초, 10 epoch 4분. train 손실 1.04 → 0.65(계속 감소).
  - 월요일 점수 흐름 9초. 보류 창 312개, p95 recon 9.897, shift 4.577. 화~금은 아직 흘리지 않았다.

## 열두 번째 작업: DD-008 합성 APT 주입, 로그 생성과 Silver(2026-11-06)

사용자가 TGN 노트북을 하는 동안 진행했다. 설계: [DD-008](design-decisions/DD-008-synthetic-apt-injection.md). 설정: [configs/synthetic/apt-injection.v1.json](../configs/synthetic/apt-injection.v1.json)(모델 점수를 보기 전에 고정).

### 코드
- [zeek_ad/synthetic_apt.py](../zeek_ad/synthetic_apt.py): 패턴 5개(beacon_https, slow_exfil, dns_tunnel, lateral_smb, internal_scan)가 conn 행과 딸린 프로토콜 로그 행을 만든다. 표준 라이브러리만 쓴다.
  - [tests/test_synthetic_apt.py](../tests/test_synthetic_apt.py) 7개 통과. `community_id`가 실제 Zeek 행의 값과 같은지, 간격·포트 상태·정답 역할·결정성을 확인한다.
- [scripts/build_synthetic_zeek.py](../scripts/build_synthetic_zeek.py) → `outputs/synthetic/apt_v1/`(9초).
  - 화~금 run-02 사본에 주입한다. 바뀌지 않은 로그는 하드 링크다. Silver가 읽는 run-manifest.json을 같이 쓴다.
  - 정답: `truth/episodes.json`(uid 목록), `truth/windows.parquet`(374창). 합성 캡처 경계: `capture-bounds.json`.

### 검사
- 주입 행을 빼면 각 로그가 원본과 바이트 단위로 같다(conn, dns, ssl, dce_rpc × 4일, SHA-256 대조).
- 정답 창이 에피소드끼리, CIC 정답 창과 겹치지 않는다. 주입 uid는 모두 새 값이다.
- Silver(`outputs/synthetic/apt_v1/silver/conn_v1`): 네 날 모두 격리 0행, Bronze 행 수 일치. 예: 화요일 323,342 + 274 = 323,616.

### 주입 결과(20건)
| 날 | lateral_smb | internal_scan | beacon_https | slow_exfil | dns_tunnel |
| --- | --- | --- | --- | --- | --- |
| 화 | .14 14:49, 50분 | .17 13:33, 56분 | .8 13:27, 118분 | .19 16:21, 114분 | .25 12:29, 30분 |
| 수 | .8 13:56 | .5 18:12 | .19 13:58 | .12 17:04 | .9 16:18 |
| 목 | .5 15:06 | .14 13:15 | .16 16:32 | .15 12:43 | .8 15:41 |
| 금 | .12 12:56 | .19 15:23 | .25 16:33 | .16 13:42 | .17 17:10 |

- 시각은 UTC다. 하루 주입 conn은 274~281행이다. beacon은 약 28연결, 느린 유출 16연결, DNS 터널 약 180질의, 측면 이동 16연결, 정찰 36연결이다.

### 남은 일
- Gold·이벤트 표·TGN 그래프를 합성 캡처로 다시 만든다. 지금 스크립트는 CIC 캡처 설정이 고정되어 있어 `--captures` 인자를 추가해야 한다. 월요일은 원래 것을 그대로 쓴다.
- 모델 점수 → 합성 Recall@N(주: CIC 사건 제외 큐, 보조: 전체 큐), 패턴별 결과.

## 열세 번째 작업: DD-006 수정 절 1·2번, 로그 특징 추가와 재학습(2026-11-06)

사용자 결정(Q33): TGN만 프로토콜 로그를 보는 상태를 고쳐, 창 모델(꼬리 희귀도·IF·Transformer)도 같은 로그 정보를 쓰게 한다. **결과 노출 이후의 변경이다.**

### 1번: Gold v2
- [docs/feature-dictionary-v2.md](feature-dictionary-v2.md). v1 18개 + 로그 24개 = 42개. `outputs/gold/conn_features_v2/`(23초).
- 검사 통과: 행 수 v1과 같음, 키 유일, null 없음, 창마다 이벤트 행 수 = `conn_count`, 독립 재계산 242값 일치.

### 2번: 재학습·평가
- 코드 변경: `baselines.Preprocessor`·`TailRarity`가 특징 목록을 받는다(기본값 v1). `run_baselines.py --gold`, `build_sequences.py --config`, `run_transformer.py --config`를 추가했다. 평가 공통 함수는 Gold 경로를 받는다.
  - v1 재현 확인: 바꾼 코드로 v1 IF·꼬리 희귀도 점수를 다시 계산해 저장된 점수와 완전히 같음을 확인했다.
- Transformer v2: [configs/models/transformer.v2.json](../configs/models/transformer.v2.json). 모델·학습 설정은 v1과 같고 입력만 42개 특징이다(토큰 45차원). 표준화 규칙도 v1과 같다(창 단위 로그 특징의 |z| 최대 19라 TGN 같은 하한이 필요 없었다).

| 모델 | 화@10 | 수@10 | 목@10 | 금@10 | 합계@10 [95% 구간] | 합계@50 |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| 꼬리 희귀도 v1 | 0/2 | 4/5 | 2/6 | 2/3 | 8/16 [0.25, 0.75] | 9/16 |
| 꼬리 희귀도 v2 | 2/2 | 2/5 | 2/6 | 2/3 | 8/16 [0.25, 0.75] | 13/16 |
| IF v1 | 0/2 | 0/5 | 0/6 | 0/3 | 0/16 [0.00, 0.00] | 10/16 |
| IF v2 | 0/2 | 2/5 | 1/6 | 1/3 | 4/16 [0.06, 0.44] | 13/16 |
| Transformer v1 | 0/2 | 4/5 | 2/6 | 2/3 | 8/16 [0.25, 0.75] | 9/16 |
| Transformer v2 | 0/2 | 4/5 | 2/6 | 2/3 | 8/16 [0.25, 0.75] | 11/16 |

- 꼬리 희귀도 v2는 Patator 2건을 처음으로 잡았다(화 5위·8위, SSH·FTP 인증 실패 특징). 대신 동점이 많아졌다(포화값 log(1287)=7.16). 경계 동점 평균 Recall@10은 화 0.91, 수 0.39, 목 0.23, 금 0.70이다. 기댓값으로 약 7.3/16이고, 8/16은 고정 해시 순서의 값이다.
- IF v2는 0 → 4/16이다. 수요일 DoS 3건이 한 사건(1위)에 겹쳐 일대일 대응은 2다.
- Transformer v2는 @10이 같고 @50이 9 → 11이다. Patator가 후보가 됐지만 31·50위다.
- 긴 연결 진단: 보류 상위 10의 긴 연결 지배 창 비율은 IF v2 0%, 꼬리 v2 10%, Transformer v2 0%. 문제 없음. (`outputs/diagnostics/long_connections.json`은 마지막 실행 모델만 담는다. v1 값은 앞 작업 기록에 있다.)
- 16건 구간이 모두 겹친다. 확장 전후 차이를 확실하다고 말할 수 없다. 합성 주입(DD-008) 평가에서 v1·v2를 같이 본다.

## 열네 번째 작업: DD-008 합성 평가, 합성 Gold·그래프와 창 모델 점수(2026-11-08)

사용자가 TGN 노트북을 하는 동안 진행했다. 모델은 다시 학습하지 않았다. 평가 규칙은 [DD-008](design-decisions/DD-008-synthetic-apt-injection.md) 그대로다.

### 코드
- [configs/synthetic/captures.syn1.v1.json](../configs/synthetic/captures.syn1.v1.json): 합성 캡처의 Zeek 폴더와 용도(원래 날과 같다).
- `build_gold.py`·`build_tgn_events.py`에 `--captures`·`--bounds`, `build_tgn_dataset.py`에 `--events`(여러 개)·`--captures`(이어 붙일 순서)를 추가했다. 기본값은 기존 CIC 동작과 같다.
- [zeek_ad/synthetic_eval.py](../zeek_ad/synthetic_eval.py): 하루 큐에서 CIC confirmed 사건을 뺀 주 큐와 전체 큐를 같이 평가한다. CIC 정답 창은 합성 캡처 ID로 옮겨 겹침을 판정한다. [tests/test_synthetic_eval.py](../tests/test_synthetic_eval.py) 4개 통과.
- [scripts/run_synthetic_eval.py](../scripts/run_synthetic_eval.py): 월요일(원래 Gold) + 합성 네 날(합성 Gold)을 합쳐 점수를 매긴다.
  - 꼬리 희귀도·IF는 같은 월요일 train·같은 seed로 다시 적합한다(결정적). Transformer는 원래 run의 체크포인트를 불러온다.
  - 원래 run과 월요일 점수(최대 차이 0)·임계값이 같지 않으면 멈춘다. 여섯 모델 모두 완전히 같았다.
  - 처음에 IF가 달랐다. 합친 표를 키 순서로 정렬해 train 행 순서가 바뀌었고, IF 표본 추출이 행 순서에 따라 달라서다. 월요일 행의 원래 순서를 지키게 고쳤다.
  - 첫 두 실행은 위 문제와 JSON 불리언 문자열 문제로 결과 폴더와 MLflow run을 지우고 다시 돌렸다.

### 생성물(`outputs/synthetic/apt_v1/`)
- `gold/conn_features_v1`(6,762창, 33초), `events/tgn_v1`(54초), `gold/conn_features_v2`(27초), `graphs/tgn_v1`(월요일 원래 이벤트 + 합성 네 날, 35초).
- 검사:
  - TGN `encoding.json`이 원본과 완전히 같다. 주입되지 않은 이벤트의 인코딩 값(t, 범주, history, 수치, DNS 가중치, 출발·도착 IP, 노드 특징)도 원본 그래프와 같다. 노드는 19,093 → 19,101(새 외부 IP 8개).
  - 이벤트 표: 주입 uid 1,109개를 빼면 원본과 같다.
  - Gold v1·v2: 원래 창 6,632개 중 316개가 바뀌고 130개가 새로 생겼다. 바뀐 창 446개는 정답 창 374개 + DNS 서버(192.168.10.3) responder 창 72개다. 정답 창은 모두 Gold 행이 있다.

### 결과: 합성 에피소드 20건, `outputs/eval/20261108T120813Z-synthetic_apt_v1/`

| 모델 | 주 @10 [95% 구간] | 주 @50 [95% 구간] | 전체 @10 | 전체 @50 |
| --- | --- | --- | ---: | ---: |
| 꼬리 희귀도 v1 | 4/20 [0.05, 0.40] | 9/20 [0.25, 0.65] | 4 | 7 |
| IF v1 | 4/20 [0.05, 0.40] | 4/20 [0.05, 0.40] | 4 | 4 |
| Transformer v1 | 4/20 [0.05, 0.40] | 9/20 [0.25, 0.65] | 4 | 8 |
| 꼬리 희귀도 v2 | 7/20 [0.15, 0.55] | 11/20 [0.35, 0.75] | 7 | 10 |
| IF v2 | 2/20 [0.00, 0.25] | 6/20 [0.10, 0.50] | 1 | 5 |
| Transformer v2 | 4/20 [0.05, 0.40] | 11/20 [0.30, 0.75] | 4 | 8 |

패턴별 주 큐 최고 순위(화·수·목·금, — = 후보 아님 또는 순위 없음):

| 패턴 | 꼬리 v1 | IF v1 | Transformer v1 | 꼬리 v2 | IF v2 | Transformer v2 |
| --- | --- | --- | --- | --- | --- | --- |
| internal_scan | 1·1·2·2 | 6·8·8·8 | 1·1·1·1 | 3·1·3·2 | 15·6·9·18 | 1·1·1·1 |
| lateral_smb | —·—·27·— | 80·60·107·53 | 19·22·27·17 | —·—·39·— | 11·67·56·52 | 19·21·28·18 |
| slow_exfil | 16·18·17·18 | —·55·—·— | 83·57·—·— | 30·**7**·**4**·24 | —·—·63·— | —·112·107·— |
| dns_tunnel | — | 78·—·—·— | 64·—·—·— | **1**·117·—·13 | 62·—·—·— | 133·—·85·— |
| beacon_https | —·—·84·— | 69·—·63·— | 87·111·54·49 | —·118·105·— | 73·—·47·79 | 60·49·43·49 |

- 해석:
  - 창 모델 셋 모두 느린 정찰(internal_scan)만 안정적으로 잡는다. 대상 6개 × 포트 6개라 창 하나의 거절 비율·상대 수가 크게 바뀐다.
  - beacon과 느린 유출은 5~10분에 연결 하나뿐이라 창 집계에 묻힌다. 창 하나만 보면 정상 HTTPS와 구별되지 않는다. 이벤트 단위 모델(TGN)이 다룰 대상이다.
  - Transformer는 측면 이동을 네 날 모두 17~28위에 올린다(후보 생성은 된다). 꼬리 희귀도는 한 날만 후보다.
  - 로그 특징(v2)이 꼬리 희귀도에서 유출 2건·DNS 터널 1건을 상위 10에 올렸다(DNS 질의 길이·엔트로피, SSL 개수). 다만 꼬리 v2는 경계 동점이 커서(22~29개 중 10자리) 동점 평균 기댓값은 약 5.4/20이고 7/20은 고정 해시 순서의 값이다.
  - IF v2는 v1보다 낮다(4 → 2). IF는 v1·v2 모두 정찰 외 패턴을 상위 50에 거의 올리지 못한다.
  - CIC 사건을 빼서 함께 빠진 합성 사건은 모든 모델·날에서 0이다. 주 큐와 전체 큐의 차이는 CIC 사건이 빠져 순위가 올라간 효과뿐이다.
  - 구간이 모두 겹친다. 20건이라 모델 사이 차이를 확실하다고 말할 수 없다.
- 남은 일: TGN 공식 실행 뒤 `tgn_recon`·`tgn_shift`를 같은 스크립트에 넣는다. 합성 그래프는 노드 수가 원본보다 8개 많아 메모리 버퍼 크기가 다르다. 학습 parameter만 불러오고 메모리는 캡처마다 0에서 시작하므로 결과에는 영향이 없다.

## 열다섯 번째 작업: DD-007 TGN 공식 실행·평가와 합성 평가(2026-11-10)

### 코드
- [zeek_ad/tgn_model.py](../zeek_ad/tgn_model.py): 사용자가 노트북 04에서 작성한 `EdgeEncoder`, `GraphEmbedding`, `EdgeDecoder`, `event_loss`, `weighted_mean`, `latent_shift`를 옮겼다(사용자 요청으로 Claude가 옮김).
  - 노트북의 전역 변수(N_CAT, CAT_SIZES, `make_edge_encoder`, memory 등)를 쓰던 부분만 인자·속성으로 바꿨다. 계산은 같다.
  - 노트북의 주어진 코드(메시지 함수, build_tgn, forward_batch, update_graph, 학습·점수 흐름, 창 집계)는 `EdgeMessage`, `EventTGN`, `train_epoch`, `score_capture`, `window_scores`로 옮겼다. `window_scores`에 NAT 제외 인자를 더했다.
  - 체크포인트는 학습 parameter만 담는다. 메모리 버퍼는 노드 수에 따라 크기가 다른 상태라 뺀다.
- [scripts/run_tgn.py](../scripts/run_tgn.py): 입력 확인(그래프 파일 해시, 설정 data 절과 인코딩 열 목록) → 10 epoch 학습 → 하루마다 메모리를 비우고 점수 → Gold v1 창에 일대일로 옮김 → `tgn_recon`·`tgn_shift` 따로 평가 → NAT 제외 진단·점수 감쇠 진단 → MLflow(단계 3c).
  - 이벤트 점수는 `outputs/eval/20261110T104214Z-tgn_recon/event_scores.npz`에 있다(MLflow에는 올리지 않음).
- 노트북과 같은 결과: train 손실이 epoch마다 소수점 끝까지 같다(1.0410 → 0.6544). 보류 p95 recon 9.8967, shift 4.5767도 같다. 학습 307초, 하루 점수 10~16초.
- 공식 실행 뒤 고친 것: 합성 평가에서 체크포인트를 불러올 때 공유 parameter(`gnn.time_enc` = `memory.time_enc`)가 "빠졌다"고 잘못 판정해 `load_parameter_state`의 허용 목록을 고쳤다. 그래서 TGN run의 lineage에 남은 `tgn_model.py` 해시는 이 수정 전 파일이다. 학습·점수 계산 부분은 바뀌지 않았다.

### 결과: CIC 화~금, `outputs/eval/20261110T104214Z-tgn_recon`·`-tgn_shift`

| 모델 | 화@10 | 수@10 | 목@10 | 금@10 | 합계@10 [95% 구간] | 합계@50 |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| **TGN recon** | 1/2 | 5/5 | 2/6 | 3/3 | **11/16** [0.44, 0.94] | 13/16 |
| TGN shift | 2/2 | 3/5 | 2/6 | 1/3 | 8/16 [0.25, 0.75] | 10/16 |
| (참고) 꼬리 v1·v2, Transformer v1·v2 | | | | | 8/16 | 9~13/16 |
| (참고) NAT 연결 수(진단) | | | | | 12/16 | |

- 경계 동점은 화·목·금에 2개 중 1자리가 있지만 Recall이 바뀌지 않는다(최소=최대).
- 공격별 최고 순위(recon / shift): FTP-Patator 9/3, SSH-Patator 33/1, DoS 4종 2·2·1·1 / 1·1·8·2, Heartbleed 3/—, 웹 공격 6·56·— / 6·79·79, Infiltration 스캔 —/89, Infiltration Vista 1/1, MAC 48/—, Botnet 5/20, PortScan 2/1, DDoS 1/—.
- NAT 제외 진단(상대가 172.16.0.1인 연결을 뺀 창 최댓값):
  - recon 11 → 6/16. 수요일 DoS·Heartbleed·DDoS처럼 공격 연결 자체가 NAT에서 오는 에피소드가 내려간다. 공격 연결을 빼면 공격 신호가 없어지는 것이므로 당연한 결과이기도 하다.
  - NAT 연결 자체가 낯선지 따로 봤다. 정답 창 밖의 NAT 연결(3,194개)은 recon 중앙값 1.59, 임계값 이상 1.0%다. 정답 창 안의 NAT 연결은 중앙값 4.92, 2.9%다. 비NAT 정상 연결은 중앙값 0.09, 0.03%다. NAT 연결은 원래 점수가 높은 편이지만, 공격 연결이 그보다 더 높다.
  - shift는 8 → 8/16로 그대로다.
- 해석에 주의할 점: Patator 2건(화)의 창 최고 점수는 공격 연결(NAT)이 아니라 같은 창의 192.168.10.25 → 192.168.10.50 연결(DNS, 임의 포트 REJ)에서 나왔다. Patator 공격 연결의 recon은 p95 6.4(FTP)·5.5(SSH)로 임계값보다 낮다. 그래서 Patator를 "공격 연결을 보고 잡았다"고 말할 수 없다.
- 점수 감쇠 진단(confirmed 에피소드의 자산·역할 계열 30개, 마지막 1/3 중앙값 ÷ 처음 1/3 중앙값): recon 중앙 0.96, 절반 이하로 떨어진 계열 2개. shift 중앙 0.98, 0개. 메모리 갱신으로 반복 공격에 익숙해지는 현상은 뚜렷하지 않다.

### 합성 평가(DD-008): `outputs/eval/20261110T104445Z-synthetic_apt_v1/`
- [scripts/run_synthetic_eval.py](../scripts/run_synthetic_eval.py)에 TGN을 넣었다. 합성 그래프(노드 19,101개)로 모델을 새로 만들고 원래 run의 parameter를 불러온다. 월요일 점수가 원래 run과 완전히 같았다(최대 차이 0, 임계값 같음). 노드 번호가 달라도 계산이 같다.

| 모델 | 주 @10 [95% 구간] | 주 @50 | 전체 @10 | 전체 @50 |
| --- | --- | ---: | ---: | ---: |
| TGN recon | 2/20 [0.00, 0.25] | 9/20 | 0 | 6 |
| TGN shift | 2/20 [0.00, 0.25] | 7/20 | 1 | 6 |
| (참고) 꼬리 v2 / Transformer v1·v2 | 7/20 / 4/20 | 11 / 9·11 | | |

패턴별 주 큐 최고 순위(화·수·목·금):

| 패턴 | TGN recon | TGN shift |
| --- | --- | --- |
| beacon_https | 61·33·15·**5** | 67·—·**2**·— |
| lateral_smb | 48·11·—·34 | — |
| internal_scan | —·113·**6**·— | 18·13·35·**8** |
| slow_exfil | —·—·44·— | —·35·91·39 |
| dns_tunnel | 14·—·—·— | — |

- 해석:
  - TGN recon은 beacon 순위가 5~61위로 창 모델(가장 좋은 Transformer v2가 43~60위)보다 높다. 그래도 상위 10에는 한 날만 든다.
  - 창 모델이 안정적으로 잡던 느린 정찰은 TGN이 약하다. 연결 하나하나는 흔한 REJ라 복원이 쉽고, 창 단위의 "여러 대상·포트" 신호를 이벤트 점수의 최댓값으로는 보지 못한다.
  - 전체 큐(CIC 사건 포함)에서는 0~1/20이다. CIC 공격 사건이 큐 위쪽을 차지한다.
  - 20건이라 구간이 넓다. TGN과 창 모델은 서로 다른 패턴을 잡는다는 것이 이번 결과의 요점이다. 결합 결정의 근거로 쓴다.

## 열여섯 번째 작업: DD-009 ML·DL 결합(순위 번갈아 합치기) 평가(2026-11-11)

사용자 결정: TGN recon·꼬리 희귀도 v2·Transformer v2의 하루 큐를 순위대로 번갈아 합친다([DD-009](design-decisions/DD-009-rank-interleave-fusion.md), 설정 [fusion.v1.json](../configs/models/fusion.v1.json), 결합 평가 전 고정). 세 모델의 단독 결과를 본 뒤의 결정이다.

### 코드
- [zeek_ad/fusion.py](../zeek_ad/fusion.py) `fuse_round_robin`. [tests/test_fusion.py](../tests/test_fusion.py) 3개 통과(설명 예시 A, D, B, E, G, C, F, H 그대로, 창이 겹쳐야 같은 사건, 큐가 끝난 모델은 건너뜀).
- [scripts/run_fusion.py](../scripts/run_fusion.py): 이미 끝난 run의 창 점수와 임계값을 그대로 쓴다(다시 학습·채점하지 않음). 모델 단독 큐를 다시 만들어 원래 run의 Recall@N과 같은지 먼저 확인한다(CIC·합성 모두 일치). 결과 `outputs/eval/20261111T014619Z-fusion_v1/`, MLflow 단계 태그 `3-fusion`.

### 결과

| 큐 | CIC @10 [95% 구간] | CIC @50 | 합성 주 @10 [95% 구간] | 합성 주 @50 | 합성 전체 @10 |
| --- | --- | ---: | --- | ---: | ---: |
| **결합 v1** | 8/16 [0.25, 0.75] | **14/16** | 5/20 [0.10, 0.45] | **13/20** | 5/20 |
| TGN recon | **11/16** [0.44, 0.94] | 13/16 | 2/20 | 9/20 | 0/20 |
| 꼬리 희귀도 v2 | 8/16 | 13/16 | **7/20** | 11/20 | 7/20 |
| Transformer v2 | 8/16 | 11/16 | 4/20 | 11/20 | 4/20 |

- 상위 10에서는 결합이 가장 좋은 단독 모델보다 낮다(CIC는 TGN보다 3건, 합성은 꼬리 v2보다 2건 적다). 상위 50에서는 결합이 두 평가 모두 가장 높다.
- 이유: 상위 10 예산이 세 모델로 나뉘어 모델마다 3~4자리다. 단독으로 4~9위였던 사건이 결합 큐에서는 10위 밖으로 밀린다. 예: FTP-Patator는 꼬리 5위·TGN 9위 → 결합 12위, 웹 공격 ep-008은 TGN 6위 → 결합 16위, 합성 beacon은 TGN 5~61위 → 결합 12~139위.
- 상위 10 사건 대부분을 두세 모델이 함께 꼽았다(겹쳐서 건너뛴 기록). 모델들이 같은 정상 이상치도 함께 높게 본다는 뜻이고, 그 자리를 공격이 아닌 사건이 차지한다.
- 합성 패턴별(주 큐): 정찰 4/4 상위 10(2~3위), DNS 터널 1/4, 나머지 0. 측면 이동 28~65위, 느린 유출 11~68위, beacon 12~139위.
- 구간이 모두 겹친다. 결합이 단독보다 낫다거나 못하다고 확실히 말할 수 없다. 결과를 보고 규칙(모델 수, 순서, 몫)을 바꾸지 않는다. 바꾸면 결과에 맞춘 조정이 된다.
