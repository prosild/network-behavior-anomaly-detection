# 단계 5 진행 기록

단계 5 범위(설계 9절, DD-002, DD-001, DD-010): 5a pgvector RAG(ATT&CK), 5b Evidence Builder·템플릿/LLM 보고서·LangGraph·Jev·Slack(dry-run)·사건 상태 흐름·알림 중복 억제.

## 첫 작업: 5a-1·2 ATT&CK 문서 가져오기와 탐지 절 다시 채우기(2026-11-12)

### 준비
- pgvector 확장: 신뢰(trusted) 확장이 아니라 superuser만 만든다. [deploy/postgres/init/02-extensions.sh](../deploy/postgres/init/02-extensions.sh)로 `zeekad` DB public 스키마에 만들고, 앱 역할에는 USAGE만 줬다(CREATE는 계속 막힘). 이미 떠 있는 DB에는 같은 스크립트를 한 번 실행했다. 접속 search_path는 `zeekad,public`.
- 표: [db/migrations/003_rag.sql](../db/migrations/003_rag.sql) — `rag.attack_document`(기법 하나 = 문서 하나), `rag.document_embedding`(모델마다 한 행, 문서가 706개라 인덱스 없이 정확히 비교).

### 가져오기([scripts/build_attack_corpus.py](../scripts/build_attack_corpus.py))
- 사용자 실습 DB(`attack_rag`, 읽기만)의 technique 706행을 스냅샷 `outputs/rag/attack_v20.1/practice_documents.jsonl`(sha256 `9e03775c…`)로 저장했다. 연습용 sample 3행은 뺐다.
- ATT&CK 원본 `enterprise-attack.json`을 같은 폴더에 복사했다(Enterprise 20.1, sha256 `539a843a…`). 706행 모두 원본의 유효한 기법과 ID가 맞다.
- 탐지 절: 원본의 `detects` 관계(detection strategy → 기법) 706개, strategy의 analytic, analytic의 로그 소스(데이터 구성 요소)로 만들었다. 폐기된 strategy 2개는 뺐다. 탐지 절이 없는 기법은 0개다(실습 DB는 706개 모두 비어 있었다).
  - 예: T1071.001 Web Protocols → DET0027, 플랫폼별 analytic 5개, 로그 소스에 `NSM:Flow: http.log, ssl.log`·`conn.log`(Zeek 로그)가 나온다. T1021.002 → DET0530(SMB 관리 공유 + 원격 서비스 생성).
  - 네트워크 데이터 구성 요소가 있는 문서: Network Traffic Flow 92, Network Connection Creation 155, Network Traffic Content 140.
- 최종 본문 길이(문자): 중앙 3,160, p95 6,021, 최대 10,401.

## 둘째 작업: 5a-3 질의 세트 고정과 BM25 기준선(2026-11-14)

### 질의 세트 고정
- 사용자 확인 뒤 [configs/rag/query-set.v1.json](../configs/rag/query-set.v1.json)을 `frozen`으로 바꿨다(sha256 `187f3619…`). 고정 전에는 어떤 검색 결과도 보지 않았다. 바꾸려면 v2를 새로 만든다.

### 검색 대상 글([zeek_ad/rag.py](../zeek_ad/rag.py) `embedding_text`)
- 머리(이름·분류·전술·플랫폼) + 설명 + 탐지 절만 쓴다. 완화책과 사용 그룹(Used By)은 뺀다. 둘은 행동 묘사가 아니라 대응책·행위자 목록이라 네트워크 행동 질의와 엉뚱하게 겹칠 수 있다.
- 임베딩 모델도 같은 글을 쓴다. 비교 결과 파일에 글 전체의 해시를 남긴다.

### BM25 기준선([scripts/eval_rag_retrieval.py](../scripts/eval_rag_retrieval.py) `--method bm25`)
- rank-bm25 `BM25Okapi`(k1=1.5, b=0.75), 소문자 영숫자 토큰, 어간 추출 없음. 상위 20개까지 본다.
- 결과(`outputs/rag/eval/20261113T173251Z-bm25`): **hit@1 7/16(0.44), hit@3 11/16(0.69), hit@5 12/16(0.75), MRR 0.573**.
- 잘 맞은 것: 무차별 대입(q01·q02·q06), DoS(q03·q04·q10), 웹 공격(q07). 질의와 문서가 같은 단어(failed login, HTTP, flood)를 쓴다.
- 못 맞은 것: 스캔 3건. q08(20위)·q09(20위 밖)·q16(17위). T1046 문서는 "scan"·"service discovery"로 쓰고, 질의는 "connects to many ports, rejected"로 행동만 쓴다. 단어가 겹치지 않으면 BM25는 찾지 못한다. 임베딩이 이 차이를 메우는지가 다음 비교의 핵심이다.
- 중간: 비콘 q12(7위). 1위는 T1090.001(Internal Proxy). "internal", "connections" 같은 흔한 단어가 점수를 끌었다.

## 셋째 작업: 5a-4 Gemini 임베딩 검색(2026-11-14)

### 준비
- `google-genai==3.2.0` 설치(임베딩과 DD-011 판단 모델이 같은 SDK). 의존성 때문에 `tenacity`가 9.2.1 → 9.1.4로 내려갔다(`pip check` 이상 없음, langchain-core도 허용). requirements·잠금 파일 갱신.
- 판단 모델 결정: [DD-011](design-decisions/DD-011-gemini-decision-model.md)(Jev → `gemini-decision-1`).

### 문서 임베딩([scripts/embed_attack_docs.py](../scripts/embed_attack_docs.py))
- `gemini-embedding-001`, 768차원, 작업 유형 `RETRIEVAL_DOCUMENT`(질의는 `RETRIEVAL_QUERY`). 768은 3072를 잘라 쓴 것이라 길이 1로 다시 정규화해 저장한다.
- 글은 BM25와 같은 `embedding_text`. 가장 긴 글이 1,692토큰이라 모델 한도(2,048) 안이다(잘린 문서 없음).
- 무료 등급 한도는 분당 3만 토큰이다. 처음엔 50개 묶음(약 3만 토큰 이상)이 한도보다 커 재시도해도 계속 429였다. 묶음을 추정 2만 토큰 이하로 나누고, 보낸 토큰만큼 기다리게 고쳐 28묶음으로 넣었다(약 15분).
- `rag.document_embedding`에 706행, 한 트랜잭션. 다시 실행하면 글 해시가 같아 "새로 만듦 0개"(확인).

### 결과(`outputs/rag/eval/20261113T181132Z-gemini`, 질의 벡터 `query_vectors.npy` 함께 저장)

| 방법 | hit@1 | hit@3 | hit@5 | MRR |
| --- | --- | --- | --- | --- |
| BM25 | 7/16 (0.44) | 11/16 (0.69) | 12/16 (0.75) | 0.573 |
| Gemini 768 | 10/16 (0.62) | 12/16 (0.75) | **15/16 (0.94)** | **0.724** |

- 스캔 3건이 좋아졌다: q08 20→4위, q09 없음→5위, q16 17→5위. 단어가 달라도 뜻이 가까운 문서를 찾는다. 다만 1위는 여전히 T1090.001(Internal Proxy)·T1205.001(Port Knocking)이다. "많은 포트", "internal"이 그쪽 문서와도 가깝다.
- 1위로 올라간 것: q11 비콘(ARES), q13 느린 유출(T1048), q14 DNS 터널(T1071.004), q15 측면 이동(T1021.002).
- 남은 약점: q12 HTTPS 비콘 10위(BM25 7위). 1위 T1133 External Remote Services. "TLS 443, 정해진 간격" 묘사가 C2보다 원격 접속 서비스와 가깝게 잡혔다.
- 내려간 것: q06 웹 무차별 대입 1→3위(T1110.004 Credential Stuffing이 1위. 같은 T1110 계열이라 실제 해는 작다).

## 넷째 작업: 5a-5 bge 로컬 임베딩·RRF 혼합 비교와 검색 방법 선택(2026-11-14)

### 방법
- [scripts/eval_rag_retrieval.py](../scripts/eval_rag_retrieval.py)를 여러 방법을 한 번에 비교하도록 바꿨다(`--methods`, 기본 5개). 방법마다 전체 순위를 만들고 평가는 상위 20까지 본다.
- bge-base-en-v1.5(Hugging Face commit `a5beb1e3…` 고정, GPU): 한 번에 512토큰까지만 읽는데 문서 706개 중 507개가 넘는다(실측). 그대로 넣으면 대부분 탐지 절이 잘리므로, 머리(이름·분류·전술·플랫폼)를 붙인 510토큰 이하 조각으로 나눠 임베딩하고 문서 점수 = 질의와 가장 가까운 조각(max)으로 했다. 조각 1,343개(문서당 최대 5개, 잘린 조각 0). 질의에는 모델 카드 권장 접두어를 붙였다. 조각 벡터는 DB에 넣지 않고 평가 때 계산한다(DB 표는 문서당 한 행).
- RRF: 문서 점수 = Σ 1/(60 + 방법별 순위). k=60은 표준 값이고 결과를 보고 바꾸지 않았다.

### 결과(`outputs/rag/eval/20261114T043204Z-compare`)

| 방법 | hit@1 | hit@3 | hit@5 | MRR | 로컬 |
| --- | --- | --- | --- | --- | --- |
| BM25 | 0.438 | 0.688 | 0.750 | 0.573 | 예 |
| **Gemini 768** | **0.625** | **0.750** | **0.938** | **0.724** | 아니오 |
| bge(조각 max) | 0.188 | 0.625 | 0.750 | 0.445 | 예 |
| RRF BM25+Gemini | 0.562 | 0.750 | 0.812 | 0.680 | 아니오 |
| RRF BM25+bge | 0.500 | 0.688 | 0.812 | 0.645 | 예 |

- BM25·Gemini 수치는 앞 작업 단독 실행과 같다(재현).
- bge는 1위가 약하다(3/16). 주제가 같은 다른 기법을 앞에 둔다. 예: q02(SSH 인증 실패 반복)에서 T1133 외부 원격 서비스·T1021.004 SSH 원격 접속·T1563.001 SSH 하이재킹이 앞서고 무차별 대입은 7위. "실패가 반복된다"는 행동보다 "SSH"라는 주제에 끌린다. 대신 HTTPS 비콘 q12는 4위로 다섯 방법 중 가장 좋다.
- RRF는 BM25가 크게 틀린 질의(q09 스캔: BM25 20위 밖)에서 Gemini 순위를 끌어내린다(5→16위). 두 방법이 서로 다른 질의에서 틀리는 경우가 아니라, BM25가 틀리는 곳에서 Gemini가 맞는 구조라 합쳐도 이득이 없었다.

### 선택
- 규칙(hit@5 → MRR → 로컬 우선): **Gemini 768**. 설정 [configs/rag/retrieval.v1.json](../configs/rag/retrieval.v1.json)(top_k 5).
- 질의 임베딩 호출이 실패하면 로컬 BM25로 대신 찾고 그 사실을 기록한다(LLM 실패가 조사 흐름을 막지 않게 한다, 설계 9.1절).
- 한계: 질의 16개라 차이가 크지 않다(Gemini 15/16, RRF 13/16, BM25·bge 12/16). 선택은 이 질의 세트 기준의 판단이다. q12(합성 HTTPS 비콘)는 Gemini가 10위라, 5b 보고서에서 이 패턴은 검색 근거가 약할 수 있다.

## 다섯째 작업: 5b-1 LLM 입력(허용 목록·가명)·검색 질의 문장·템플릿 보고서(2026-11-15)

### 사례 집합([configs/agent/cases.v1.json](../configs/agent/cases.v1.json))
- 개발(dev): CIC 화·수 결합 큐 상위 10건씩 + 합성 화·수 상위 5건씩 = 30건. 평가(eval): 목·금 같은 기준 30건. 설계 9.2절대로 개발 세트로 규칙·프롬프트를 만들고, 평가 세트 전에 동결한다.
- 합성 캡처는 같은 요일 CIC 캡처에도 있는 사건(자산·역할·시작 시각 같음)을 빼고 고른다. 합성 화요일 큐 상위 10건 중 5건이 CIC 화요일과 같은 사건이었다.

### LLM 입력([zeek_ad/llm_input.py](../zeek_ad/llm_input.py), `llm-input.v1`)
- 근거(evidence.v1)를 사실 목록(`F01`…)으로 펼친다. 보고서 주장마다 사실 ID를 달게 해서 다음 작업에서 코드가 숫자를 검사한다. 사건 하나에 사실 36\~71개.
- 값: 숫자, 불리언, 검증한 열거값(전송 계층·Zeek 서비스·연결 상태는 목록, DCE-RPC 연산 이름은 형식 검사, 나머지는 `other`), 가명, 고정 설명.
- 가명: 사건 자산 `H`, 내부 상대 `I1…`, 외부 상대 `X1…`(내부 = 자산 설정의 192.168.10.0/24). 시각은 사건 시작 기준 상대 초. Zeek uid는 보내지 않는다(조회 API로 찾는다).
- 모델 의견: 점수 대신 모델별 "사건 창 n개 중 후보 창 k개", 큐 순위, 꼽은 모델과 겹쳐 꼽은 모델. 모델끼리 점수 척도가 달라서다(DD-009).
- 시험 [tests/test_llm_input.py](../tests/test_llm_input.py) 8개 통과: IP·날짜·uid가 출력에 없음, 모르는 문자열은 `other`, 가명 일관성, 상대 시각, 질의 문장 규칙, 템플릿 주장의 사실 ID 존재.

### 검색 질의 문장(`query_sentence`)과 ATT&CK 검색
- 사실 목록에서 Zeek로 보이는 행동만 영어 문장으로 만든다(5a 질의 세트와 같은 꼴). 검색은 `retrieval.v1`(Gemini, 실패 시 BM25 대체 기록).
- 개발 세트에서 고친 것(평가 세트 전에 동결):
  - SMB·Kerberos·DCE-RPC는 "있기만 하면" 넣지 않고 연결의 10% 이상일 때만 넣는다. 도메인 환경에서는 늘 조금씩 있다. 수요일 DoS(dev-11, 15만 건 중 SMB 10건)에서 T1135 Network Share Discovery가 1위였는데, 고친 뒤 T1499.002 Service Exhaustion Flood가 1위.
  - NXDOMAIN은 DNS 질의의 10% 이상일 때만.
  - 최대 DNS 이름 길이는 쓰지 않는다. 정상 AD 질의도 72자까지 가서(개발 세트 실측) 합성 DNS 터널(라벨 40\~56자)과 구분할 수 없다. 근거에 길이 분포가 없는 한계다.
  - ICMP는 Zeek가 포트 칸에 ICMP 유형·코드를 넣으므로 포트로 쓰지 않는다.
- 결과 `outputs/agent/inputs/20261114T172854Z-dev/`(30건, 검색 gemini). 실제 IP·날짜 형식 문자열 없음.

### 템플릿 보고서(`template.v1`)
- 설계 9.1절 필드(관측 요약, 사실 ID가 달린 주장, 가능한 설명 = ATT&CK 후보 가설, 판단 한계, 추가 확인). LLM이 실패하면 이것을 쓰고, LLM 보고서와 비교하는 기준선이다.

### 다음 작업에 넣을 필수 전송 조건(기본안, 사용자에게 알림)
- (1) 결합 큐 상위 5위 이내, (2) 두 개 이상 모델이 같은 사건을 꼽음(`also_flagged_by` 비어 있지 않음). 이 조건이면 판단 모델이 보류해도 보낸다(DD-001).

## 여섯째 작업: 실제 호출 시험(정식 평가 아님, 2026-11-16)

사용자 요청: 비교 기준을 넣기 전에 지금 입력(llm-input.v1)으로 실제 응답을 본다. 개발 세트 3건(dev-11 수요일 DoS, dev-09 화요일 DC, dev-03 연결 1건 ICMP). 시험 코드와 결과: `outputs/agent/probe/`(probe_llm.py, probe-20261116T193231.json).

- 모델 선택: 공식 목록(2026-11-16 조회)에서 Flash 등급 중 버전이 날짜로 고정된 최신 `gemini-3.7-flash`(3.7-flash-08-2026)를 요청했다. `gemini-3.8-flash`는 버전 칸이 "3.0"이라 고정 여부를 확인할 수 없어 뺐다.
- **요청한 모델과 응답한 모델이 달랐다.** 세 호출 모두 응답의 `model_version`이 `gemini-3.8-flash`였다. 모델 ID를 고정해도 서버가 다른 버전으로 돌릴 수 있으므로, 호출마다 응답의 model_version을 기록해야 한다.
- 구조화 출력(JSON 스키마)은 세 건 모두 형식대로 왔다. 주장의 사실 ID는 모두 실재했고, 주장 속 숫자도 인용한 사실의 값과 같았다(셀 수 없는 "3개 모델", "상위 5개" 같은 개수 제외, 코드로 검사).
- 전송 의견(일반 LLM / gemini-decision-1):

| 사례 | LLM | 판단 모델 (확률) |
| --- | --- | --- |
| dev-11 DoS | send | send 0.41 (hold 0.28, analyst 0.24, more 0.08) |
| dev-09 DC 정상 범위 | hold | hold 0.51 (analyst 0.23, send 0.17, more 0.09) |
| dev-03 ICMP 1건 | hold | hold 0.42 (analyst 0.26, more 0.17, send 0.15) |

- 예상과 달랐던 것: 비교 기준이 없으면 dev-09(평소 범위 안의 DC)를 "보냄"으로 판단할 것이라 예상했는데, LLM은 포트 구성(DNS·NTP·Kerberos·LDAP)으로 도메인 컨트롤러를 추론해 "보류"했다. 다만 판단 한계에 "평상시 기준 통계가 없어 4,568건이 통상 수준인지 알 수 없다"고 스스로 적었다.
- 발견한 문제:
  - 모델 이름 오해: `tgn_recon`의 recon(복원 오차)을 정찰(reconnaissance)로 읽고 "정찰 모델이 탐지했으므로"라고 썼다(dev-09). 모델 이름을 뜻이 드러나는 설명과 함께 보내야 한다.
  - 단위: `dns.max_query_length` 72를 "72바이트"라고 썼다(문자 수다). 사실 이름에 단위를 붙인다.
  - 판단 모델의 확률은 평평하다(최고 0.41\~0.51). confidence를 정확도로 읽지 않는다는 DD-001 원칙이 필요한 이유다.
- 지연·토큰: LLM 13\~26초(입력 1.4\~2.7k, 출력 약 1.1k, thinking 0.5\~1.9k 토큰). 판단 모델 0.4\~1.0초.

## 일곱째 작업: llm-input.v2 비교 기준·모델 설명·단위(2026-11-16, Q41)

시험 호출에서 본 세 문제를 입력 단계에서 고쳤다. 설계 변경이 아니라 설계 9.1절의 "비교 기준" 빈칸을 채운 것이다.

### 바꾼 것([zeek_ad/llm_input.py](../zeek_ad/llm_input.py), [scripts/build_agent_inputs.py](../scripts/build_agent_inputs.py))
- **비교 기준 사실(`baseline.*`)**: 사건 창(근거의 사건 범위)의 Gold v2 특징 최대값 옆에 같은 자산·역할의 월요일 학습 창(`cic17-mon`, split `train`, 모델들이 학습한 창) p50·p95·최대를 둔다. `baseline_windows`에 사건 창 수·기준 창 수를 함께 보낸다.
  - 특징 목록은 결과를 보기 전에 정한 고정 목록이다. 연결 수·고유 상대·고유 상대 포트·보낸·받은 페이로드 바이트·미성립 비율은 늘 보낸다. 거부·ICMP 비율과 프로토콜 로그 특징 15개는 사건 최대나 기준 p95가 0보다 클 때만 보낸다.
  - 분위수는 선형 보간(pandas 기본값과 같음). 결측 창은 빼고, 기준 창이 0개면 null.
- **모델 설명(`model_descriptions`)**: 모델 이름마다 고정 설명. `tgn_recon`은 "reconstruction, not reconnaissance"를 명시했다.
- **단위**: `dns.max_query_length` → `dns.max_query_length_chars`. 비교 기준 사실 이름에도 `_per_window`·`_chars`·`_ratio`를 붙였다.
- **고정 설명(`notes`)**: 한계 문장을 LLM 입력에도 넣었다. 비교 기준은 하루(월요일)뿐이고 시간대를 맞추지 않으며, 창이 적으면 약하다는 문장을 더했다.
- 시험 [tests/test_llm_input.py](../tests/test_llm_input.py) 12개 통과(4개 추가: 분위수, 사건 대 월요일 값, 결측·빈 기준, 단위 이름).

### 결과(`outputs/agent/inputs/20261116T124442Z-dev/`)
- 30건, 사실 46\~89개. 실제 IP·날짜 형식 문자열 없음. 검색 질의 문장은 v1과 30건 모두 같다(검색 결과도 같은 입력).
- 연결 수 비교 예: dev-11 수요일 DoS 사건 최대 46,675 / 월요일 p95 31·최대 34. dev-09 DC 2,324 / p95 2,847·최대 4,999(평소 범위 안).
- **기준이 얇은 사례가 많다.** 합성 캡처 10건 중 7건이 기준 창 3개 이하이고, 2건(dev-26·27)은 0개다. 공격 대상 자산이 월요일에 응답 쪽으로 거의 나타나지 않았기 때문이다. CIC에서도 dev-03·13·17·18이 1\~2개다. 이런 사례에서 비교 기준은 판단 근거가 되기 어렵고, LLM이 그것을 한계로 적는지 다음 작업에서 확인한다.

### 같은 세 사례 다시 호출(시험 코드 그대로, `outputs/agent/probe/probe-20261116T214601.json`)

| 사례 | LLM v1 → v2 | 판단 모델 v1 → v2 |
| --- | --- | --- |
| dev-11 DoS | send → send | send 0.41 → send 0.56 |
| dev-09 DC 정상 범위 | hold → hold | hold 0.51 → hold 0.71 |
| dev-03 ICMP 1건 | hold → hold | hold 0.42 → hold 0.43 |

- 선택은 같고, 판단 모델 확률은 비교 기준이 분명한 두 건에서 뚜렷해졌다. 기준 창이 2개인 dev-03은 그대로다.
- LLM이 비교 기준을 인용했다: dev-11 "기준치(최대 34건)를 수천 배 초과", dev-09 "월요일 베이스라인 정상 범위 내". dev-03은 한계에 "월요일 기준 윈도우가 2개에 불과"라고 적었다.
- 모델 이름을 정찰로 읽은 문장, "72바이트" 문장은 없었다. dev-03의 "정찰"은 ATT&CK 후보(T1595.001 능동 스캐닝) 가설이다.
- 응답 모델 버전은 이번에도 `gemini-3.8-flash`(요청 3.7)였다.
- 사례 3건이라 개선을 일반화하지 않는다. 정식 비교는 5b-2에서 dev 30건으로 한다.

## 여덟째 작업: 5b-2 LLM 1회 보고서·검증·템플릿 대체(2026-11-16\~17)

### 구성
- 모듈 [zeek_ad/llm_report.py](../zeek_ad/llm_report.py)(`llm-report.v1`), 실행 [scripts/run_agent_reports.py](../scripts/run_agent_reports.py), 설정 [configs/agent/report.v1.json](../configs/agent/report.v1.json)(요청 `gemini-3.7-flash`, temperature 0, 시간 제한 90초, 일시 오류 재시도 1회), 시스템 프롬프트 [v1](../configs/agent/prompts/report-system.v1.txt)·[v2](../configs/agent/prompts/report-system.v2.txt).
- 호출 실패·시간 초과·형식 오류·검증 실패면 템플릿 보고서를 쓴다. LLM 출력은 실패해도 평가용으로 저장한다. 오류 기록에는 예외 종류만 남긴다(오류 문장에 입력이 섞이지 않게).
- 코드 검증(설계 9.1절 중 코드로 가능한 부분)
  - 사실 ID 실재, ATT&CK ID가 검색 후보 안에 있음(필드와 문장 둘 다).
  - 주장·설명·전송 이유: 문장 속 숫자와 가명이 **인용한 사실** 안에 있어야 한다(글자 자릿수까지 반올림 비교). 인용 사실 개수("세 모델 모두")와 고정 설명의 숫자(5분, 12칸, 모델 수 3)는 허용.
  - 관측 요약·한계·추가 확인: 사실 ID가 없어 숫자가 사실 목록 어딘가에 있는지만 본다.
  - 식별자 속 숫자(F43, X1, T1595.001, p95, gemini-3.8)와 용어("95백분위수", "4xx")는 숫자로 보지 않는다.
  - 방향·단위·해석이 맞는지는 코드로 볼 수 없다. 사람 채점에서 본다.
- 시험 [tests/test_llm_report.py](../tests/test_llm_report.py) 10개 통과.

### dev 첫 실행(프롬프트 v1, `outputs/agent/reports/20261116T133747Z-dev/`): LLM 22 / 템플릿 8
실패 8건을 하나씩 읽고 나눴다.

| 원인 | 사례 | 처리 |
| --- | --- | --- |
| 검증기 오탐 | dev-15 "95백분위수", dev-19 "4xx/5xx" | 검증기 수정(용어는 숫자로 보지 않음) |
| 사실 밖 지식 숫자 | dev-02 Windows 이벤트 ID 4768·4769·4771, dev-17 "표준 HTTPS 포트(443)" | 계속 막는다. 근거 없는 숫자를 허용하면 틀린 숫자도 걸러낼 수 없다. 프롬프트에 "숫자 대신 말로" 지시 |
| 계산한 숫자 | dev-22 600초 → "10분", dev-29 156+260 → "416바이트" | 프롬프트에 환산·합산 금지를 예시와 함께 명시 |
| 인용 누락 | dev-24 포트 22·139·5985를 말하고 해당 사실 미인용, dev-09 "I1\~I5" 범위 표기 | 프롬프트에 "언급한 값의 사실은 모두 인용, 범위 표기 금지" |

### dev 재실행(프롬프트 v2, `outputs/agent/reports/20261116T134919Z-dev/`): LLM 30 / 템플릿 0

| 항목 | v1 | v2 |
| --- | --- | --- |
| 검증 통과 | 22/30 | 30/30 |
| 주장 수 / 주장 속 숫자 | 165 / 562 | 160 / 647 |
| LLM 전송 의견(send·analyst_review·hold) | 7·15·8 | 10·11·9 |
| 평균·최대 지연 | 20.9초·44.9초 | 30.7초·65.2초 |
| 토큰(입력·출력·thinking, 30건 합) | 107k·36k·46k | 110k·37k·88k |

- 숫자를 피해서 통과한 것이 아니다. 주장 속 숫자는 오히려 늘었다.
- 대가: thinking 토큰이 약 2배, 평균 지연이 약 10초 늘었다. 규칙이 엄격해져 모델이 더 오래 검토한다고 본다(추정).
- 응답 모델 버전은 30건 모두 `gemini-3.8-flash`(요청 3.7).
- 통과 보고서 3건(dev-07·21·26)을 직접 읽었다. 숫자·가명·기준 비교·방향은 맞았고, 기준 창 0개(dev-26)는 한계로 적었다. 해석의 적절성은 남는다. 예: dev-07(화요일 .15 출발, 알려진 공격 대상 아님으로 보임)은 DNS 다량·NXDOMAIN 222건으로 DGA 가설을 들고 send를 골랐다. 전송 판단의 적절성은 다음 작업(그림자 비교·사람 라벨)에서 본다.
- 개발 세트에서 프롬프트를 고쳤으므로 30/30은 개발 세트 적합 결과다. 평가 세트(목·금)에서는 v2를 동결하고 그대로 돌린다(설계 9.2절).

## 아홉째 작업: 5b-3 Slack 전송 판단 그림자 비교, dev(2026-11-17)

### 구성
- 설정 [configs/agent/send-decision.v1.json](../configs/agent/send-decision.v1.json)
  - 정책 규칙 `policy.v1`: 필수 전송(결합 큐 5위 이내 또는 2개 이상 모델이 꼽음)이면 send, 아니면 hold.
  - 판단 모델: `gemini-decision-1`, 선택지 4개와 기준 문장, 설명문.
- 모듈 [zeek_ad/send_decision.py](../zeek_ad/send_decision.py)
  - 정책 규칙 판단, 판단 모델 호출, 세 판단을 나란히 둔 기록.
  - A단계라 실제 전송(would_send)은 정책 규칙이 정한다. 실제로 보내지는 않는다.
  - 일반 LLM 의견은 5b-2 보고서의 send_recommendation을 그대로 쓴다(추가 호출 없음).
- 실행 [scripts/run_send_decisions.py](../scripts/run_send_decisions.py)(`--show`: 보낸 요청과 받은 응답 출력), 채점 [scripts/score_send_decisions.py](../scripts/score_send_decisions.py)(정답 에피소드 대조, DD-014).
- 사용자에게 dev-07 한 건의 요청·응답을 먼저 보이고 확인받은 뒤 30건을 돌렸다. 사람 라벨은 쓰지 않는다(Q46, DD-014).

### dev 결과(`outputs/agent/send/20261117T020005Z-dev/`, scored.json)
공격 관련 14/30건이다.
- CIC 화요일 상위 10건은 모두 0건(화요일 공격은 큐 상위 10에 없음).
- CIC 수요일은 5건.
- 합성 10건 중 9건(주로 내부 스캔을 받은 쪽 사건, 연결 1\~3건).

| 방식 | 지금 보냄 | 검토·추가 근거 | 보류 | 공격 관련인데 지금 안 보냄 | 무관한데 보냄 |
| --- | --- | --- | --- | --- | --- |
| 정책 규칙(필수 전송) | 29 | 0 | 1 | 0 | 15 |
| 일반 LLM | 10 | 11 | 9 | 7(검토 5, 보류 2) | 3 |
| 판단 모델 | 8 | 5 | 17 | 8(검토 4, 보류 4) | 2 |
| 필수 전송 또는 판단 모델 send(B단계 후보) | 29 | 0 | 1 | 0 | 15 |

- **필수 전송 조건이 30건 중 29건에 걸렸다.** 사례가 결합 큐 상위 10건이라 5위 이내이거나, 여러 모델이 겹쳐 꼽은 경우가 대부분이다. 그래서 필수 전송 조건을 판단 모델이 막지 못하는 구조(DD-001)에서는 판단 모델을 붙여도 알림 수가 줄지 않는다.
- LLM과 판단 모델은 알림을 29 → 10·8로 줄였다. 대신 공격 관련 7·8건을 지금 보내지 않았고, 그중 절반 정도는 검토 요청이었다.
  - 둘 다 놓친 것: 합성 DNS 터널(dev-21)과 연결 1\~3건짜리 내부 스캔 수신 사건 일부.
  - 판단 모델이 보낸 8건 중 무관한 것은 2건(dev-08, dev-12)이다.
- 판단 모델 send 확률은 공격 관련 사건에서 평균적으로 높다(0.16\~0.63). 무관한 사건은 0.04\~0.37이라 겹친다.
- 한계: 30건, dev 세트, 큐 상위 표본이다. 보류해도 사건은 조사 큐에 남는다(DD-001).

## 열째 작업: 평가 세트(목·금) 보고서·전송 판단(2026-11-17, 동결 후)

### 동결
- 사용자 결정(2026-11-17): 필수 전송 조건을 그대로 두고 동결한다.
- 동결 기록 [configs/agent/freeze.v1.json](../configs/agent/freeze.v1.json): 2026-11-17T02:08:34Z. 입력 규칙, 검색, 보고서 프롬프트 v2, 검증기, 판단 설정, 채점 코드 등 13개 파일의 sha256.

### 실행
- 입력 `outputs/agent/inputs/20261117T020840Z-eval/`: 30건, 검색 gemini, 실제 IP·날짜 없음.
- 보고서 `outputs/agent/reports/20261117T020850Z-eval/`
  - LLM 28 / 템플릿 2
  - 평균 30.9초, 최대 70.9초
  - 토큰(입력·출력·thinking): 113k·38k·90k
  - 응답 버전 30건 모두 gemini-3.8-flash
- 전송 판단 `outputs/agent/send/20261117T022427Z-eval/`(scored.json)

### 검증 실패 2건
- eval-04: 진짜 인용 누락. 설명 2에서 "FTP 응답 실패 2건"을 쓰고, 그 값의 사실(F47)을 인용하지 않았다. 다른 설명에서는 인용했다.
- eval-30: **검증기 오탐.** "예시 연결 2"의 2는 사실 이름(`example_connection_2`)의 순번인데, 값으로 보고 걸렀다. 동결 뒤라 고치지 않았다. 평가 결과는 동결한 검증기 기준이다. 순번 표현 허용은 평가 후 검증기 v2 후보로 남긴다.

### 전송 판단(공격 관련 26/30)
공격 관련 사건의 분포:
- 목 CIC 9/10: 모두 Infiltration ep-012(감염 PC의 내부 스캔)
- 금 CIC 7/10: 봇넷 ep-015 4건, DDoS·포트스캔 ep-016·017 3건
- 합성 10/10: 내부 스캔 수신 8건, CIC ep-012 2건

| 방식 | 지금 보냄 | 검토·추가 근거 | 보류 | 공격 관련인데 지금 안 보냄 | 무관한데 보냄 |
| --- | --- | --- | --- | --- | --- |
| 정책 규칙(필수 전송) | 29 | 0 | 1 | 0 | 3 |
| 일반 LLM | 16 | 9 | 5 | 11(검토 8, 보류 3) | 1 |
| 판단 모델 | 16 | 7 | 7 | 11(검토 6, 보류 5) | 1 |
| 필수 전송 또는 판단 모델 send | 29 | 0 | 1 | 0 | 3 |

- 세 방식 모두 보낸 것: 목요일 내부 스캔 9건 전부, 금요일 DDoS·포트스캔 3건.
- LLM과 판단 모델이 지금 보내지 않은 공격 관련 사건
  - 금요일 봇넷(봇 → C2 8080, 연결 적고 규칙적): LLM은 4건 모두 검토. 판단 모델은 send 1, 검토 2, 보류 1.
  - 합성 내부 스캔 수신(연결 1\~3건): 대부분 검토·보류.
  - dev와 같은 경향이다. 근거(연결 수)가 작은 사건을 약하게 본다.
- 판단 모델 send 확률: 보낸 사건 0.35\~0.69, 보류 0.10\~0.22.

### 결론(DD-001 A단계 비교)
- LLM·판단 모델을 쓰면 알림은 29 → 16으로 줄었다. 하지만 공격 관련 11건(42%)을 지금 보내지 않았다.
- 필수 전송 조건으로 막으면 알림이 줄지 않는다. dev(29 → 29)와 eval(29 → 29) 모두 그렇다.
- 그래서 **B 단계(판단 모델 전환)는 보류하고 A 단계(정책 규칙)를 유지한다.** DD-001의 "결과가 부족하면 A를 유지하고 이유를 기록한다"에 따른 것이다.
- 판단 모델 결과는 계속 그림자로 기록해 검토 우선순위 참고로 쓴다.
- 한계
  - 사례는 큐 상위 표본 30건이고, 공격 비율이 높다(26/30).
  - CIC 사건 내용은 이미 노출된 자료라 독립 평가가 아니다(설계 9.2절).
  - 관제 경험자 라벨은 없다(DD-014).

## 열한째 작업: 5b 결과의 DB 적재와 Slack dry-run(2026-11-17)

### DB 표([005_agent.sql](../db/migrations/005_agent.sql), [006_slack_summary.sql](../db/migrations/006_slack_summary.sql))
- `agent_report`: 화면·알림용 보고서(LLM 또는 템플릿), 검증 결과, LLM 호출 기록(응답 model_version·지연·토큰·원래 출력), ATT&CK 후보.
- `send_decision`: 정책 규칙·LLM·판단 모델 판단과 would_send(A단계라 정책 규칙).
- `slack_delivery`: 기본 키 (job_id, incident_id, report_version)로 중복 기록을 막는다. dry_run이면 status recorded, 실제 전송이면 delivered_at·slack_ts.
- `slack_summary`: 작업(캡처 하루)마다 일일 요약 하나.
- [scripts/load_agent_results.py](../scripts/load_agent_results.py)로 dev·평가 60건의 파일 결과를 넣었다. 이후 LangGraph·대시보드는 DB를 읽는다(Q45).

### Slack 메시지([zeek_ad/slack.py](../zeek_ad/slack.py), [configs/agent/slack.v1.json](../configs/agent/slack.v1.json), [scripts/run_slack.py](../scripts/run_slack.py))
- Block Kit 형식이다. 들어가는 것: 헤더(캡처, 큐 순위, 자산, 역할), 가명 안내, 시간, 꼽은 모델, 관측 요약, 주요 근거 3개(사실 번호), 보고서 종류와 세 판단, "공격 확정이 아님", 근거 보기 링크.
- 가명(사용자 결정 A): H만 실제 주소로 밝히고, 상대(I*·X*)는 가명으로 둔다. Slack은 외부 서비스이고, 실제 주소는 내부 대시보드에서 본다.
- LLM 글의 `& < >`를 이스케이프한다. `<!channel>`, `<@U…>`, `<http://…|…>` 주입이 글자로만 보인다(시험으로 확인).
- 일일 요약: 조사 큐 수, 전송 판단 수, 보낸 수, 보내지 않은 사건 목록, 판단하지 않은 사건 수(표본 밖)와 전체 큐 링크.
- 시험 [tests/test_slack.py](../tests/test_slack.py) 4개 통과.

### 실행 결과(dry-run)
- 1회차: 사건 알림 58건 기록, 보내지 않음 2건(cic17-wed 10위, cic17-fri 18위), 일일 요약 8건.
- 2회차: 새로 기록 0, 이미 기록됨 58·8. 중복이 생기지 않는다.
- `outputs/slack/dry-run.jsonl` 66줄.
- 남은 일: 실제 전송(mode live)은 Slack 토큰이 생기면 붙인다. 근거 링크 주소는 NAS 배포 때 바꾼다.

## 열두째 작업: LangGraph 흐름(2026-11-17)

### 구성([zeek_ad/agent_graph.py](../zeek_ad/agent_graph.py), 실행 [scripts/run_agent_graph.py](../scripts/run_agent_graph.py))
```
      ┌→ collect_incident ─┐
START ┼→ collect_evidence ─┼→ merge → rag → write_report → decide ─┬─(need_more_evidence, 1회)→ more_evidence → decide
      └→ collect_baseline ─┘                                      └→ deliver ─┬─(analyst_review)→ analyst_review(interrupt) → END
                                                                               └→ END
```
- 입력은 DB의 (job_id, incident_id)다(Q45).
- 입력 만들기 코드를 [zeek_ad/agent_inputs.py](../zeek_ad/agent_inputs.py)로 옮기고 세 갈래(collect_incident·collect_evidence·collect_baseline)와 모으기(facts_from_parts)로 나눴다. 저장된 dev·평가 60건의 사실 목록과 똑같은지 두 번 확인했다(모듈로 옮긴 뒤, 갈래로 나눈 뒤).
- worker 계정은 대시보드 뷰를 읽지 못하므로(최소 권한), 모델별 "후보 창 / 창"을 원래 표로 계산한다(뷰와 같은 결과).
- DB 저장은 [zeek_ad/agent_store.py](../zeek_ad/agent_store.py)로 묶었다(배치 적재와 그래프가 같이 쓴다).
- checkpoint: `langgraph-checkpoint-postgres==3.2.1`. [007_langgraph.sql](../db/migrations/007_langgraph.sql)의 langgraph 스키마는 worker 계정만 읽는다. 상태에 근거 요약(실제 IP)이 들어가기 때문이다.
- analyst_review: interrupt로 멈추고, 같은 thread_id(`job_id|incident_id`)로 재개한다. 결정은 `analyst_review` 표에 남긴다. 재개하면 이 노드가 처음부터 다시 돌기 때문에, interrupt 앞의 DB 쓰기는 ON CONFLICT로 한 번만 남긴다.
- DD-002 그림과 다른 점: RAG를 병렬 갈래가 아니라 merge 뒤에 둔다. 검색 문장이 사실 목록에서 나오기 때문이다(Q48).

### 실행
- eval-12(금요일 봇넷 .5, 큐 2위)
  - 흐름: collect → rag → write_report(LLM, 30.7초, LLM 의견 analyst_review) → decide(정책 send 필수, 판단 모델 analyst_review 0.30) → deliver(Slack은 이미 같은 보고서 버전으로 기록돼 있어 새 기록 없음) → interrupt.
  - 프로세스가 끝난 뒤 7분 뒤에 새 프로세스로 `resume --action confirm`을 실행했다. 멈춘 노드부터 이어서 끝났고 analyst_review 표에 기록됐다(checkpoint 8 → 9).
- eval-14(금요일 .15, 큐 4위, 병렬 수집 버전)
  - 세 수집 노드가 같은 단계에서 실행되고 merge가 기다렸다가 모았다(사실 73개).
  - LLM hold, 판단 모델 hold, 정책 send(필수). 검토 대기 없이 끝났다.
- more_evidence 반복은 아직 실제로 지나가 본 적이 없다. dev·평가 60건에서 판단 모델이 need_more_evidence를 1순위로 고른 적이 없기 때문이다. 다음 작업에서 가짜 판단 결과를 넣는 시험으로 이 경로를 확인한다.

## 열셋째 작업: 그래프 경로 시험과 일반 함수 버전 비교(2026-11-17, DD-002)

### 경로 시험([tests/test_agent_graph.py](../tests/test_agent_graph.py), 4개 통과, zeek-ad 환경)
- DB·LLM·판단 모델을 가짜 함수로 바꿨다. 네트워크 호출은 없다.
- need_more_evidence → more_evidence → 다시 decide. 두 번째 판단은 추가 사실(context)을 받는다. 반복은 1회까지다.
- analyst_review → interrupt로 멈춤(next = analyst_review) → 같은 thread로 `Command(resume=…)` → 결정 기록 후 끝. 대기 행 INSERT는 ON CONFLICT DO NOTHING이다.
- 판단 모델 호출이 실패해도(choice 없음) 흐름은 멈추지 않는다. 정책 규칙(필수 전송)대로 보냄이 정해지고, 검토 대기로 가지 않는다.
- hold면 검토 없이 끝나고, 정책 규칙상 보냄이면 Slack 기록 함수가 한 번 불린다.

### 일반 함수 버전([zeek_ad/agent_pipeline.py](../zeek_ad/agent_pipeline.py))과 비교([scripts/compare_agent_versions.py](../scripts/compare_agent_versions.py))
- 같은 부품을 같은 순서로 부른다. 결과 표에는 쓰지 않는다(persist=False). LangGraph 쪽은 메모리 checkpoint를 쓴다.
- 평가 사례 3건(eval-11 DDoS, eval-14 .15 DNS, eval-20 봇넷). 결과: `outputs/agent/compare/20261117T120955.json`.

| 항목 | 결과 |
| --- | --- |
| 사실 목록·검색 문장·ATT&CK 후보·정책 규칙·판단 모델 선택·전송 여부 | 3건 모두 같음 |
| LLM 전송 의견 | 2건 같음, 1건 다름(eval-14: 함수 analyst_review, 그래프 hold). 그래서 검토 대기 여부도 달라졌다. temperature 0이어도 LLM 응답은 호출마다 다를 수 있다(응답 버전도 요청과 다른 3.8). 버전 차이가 아니라 LLM 변동이다 |
| 지연(함수 / 그래프, 초) | 49.5 / 33.4, 41.1 / 33.4, 23.7 / 111.1. 둘 다 거의 전부 LLM 보고서 시간이다(22\~110초). 수집·병합은 0.01\~0.06초, 그래프 자체의 부담은 측정 범위 안에서 보이지 않는다 |
| 코드 양(주석·빈 줄 제외) | 그래프 197줄(공용 도우미 약 35줄 포함), 함수 68줄 |

### 판단
- 지금 흐름에서 LangGraph가 일반 함수보다 나은 점은 **분석가 대기 → 재개**와 **반복 상한이 있는 재판단**을 그래프 구조로 보이게 하고, 상태를 checkpoint로 들고 있는 것이다. 속도 이득은 없고 코드는 약 2배다.
- 다만 지금은 분석가 결정 뒤에 할 일이 "결정 기록"뿐이다. 그래서 함수 버전도 DB 행 하나로 같은 일을 한다. 결정 뒤 단계(사건 상태 흐름: confirm → 확인 중, dismiss → 종료와 Slack 후속 알림)가 붙어야 checkpoint 재개의 이점이 실제로 생긴다. 다음 작업인 상태 흐름을 그래프의 재개 뒤 단계로 넣는다.
- LLM 응답 변동 때문에 같은 사건도 검토 대기 여부가 달라질 수 있다. 검토 대기를 LLM 의견에만 맡기지 않는 규칙(예: 판단 모델 기준만 쓰기)은 상태 흐름 작업에서 함께 본다.

## 열넷째 작업: 사건 상태 흐름과 분석가 결정 뒤 단계(2026-11-17, DD-010)

### DB([008_incident_status.sql](../db/migrations/008_incident_status.sql), [009_transition_fix.sql](../db/migrations/009_transition_fix.sql))
- `incident_status`(현재 상태, 행이 없으면 열림), `incident_status_history`(이력, 추가만).
- 상태를 바꾸는 방법은 `dashboard.transition_incident(job, incident, to, actor, reason, resolution)` 하나다.
  - SECURITY DEFINER이고 search_path를 고정했다.
  - 한 칸씩 앞으로만 간다(열림 → 확인 중 → 종료).
  - 종료에는 결론(true_positive·false_positive·benign)이 필요하다.
  - 누가·왜는 비어 있으면 안 된다. 같은 사건은 행 잠금으로 동시에 바꾸지 못한다.
- 대시보드 상태 변경 전용 계정 `dashboard_rw`를 만들었다([scripts/add_dashboard_rw.py](../scripts/add_dashboard_rw.py), 새 DB는 init/01). 함수 실행만 된다. 비밀번호는 deploy/.env의 `DASHBOARD_RW_PASSWORD`다.
  - Docker Desktop의 WSL 연동이 끊겨 docker 명령이 동작하지 않았다. 그래서 관리자 계정으로 127.0.0.1에 직접 접속해 만들었다.
- 대시보드 뷰: `dashboard.incident_status`, `dashboard.incident_status_history`, `dashboard.analyst_review_queue`(데이터 계약 v2 후보).
- dashboard_rw로 시험한 결과: 건너뛰기·역방향·결론 없는 종료·이유 없는 변경은 거부, 표 직접 읽기·쓰기는 권한 거부, 열림 → 확인 중은 성공(eval-12).
  - 008의 함수는 결론이 NULL일 때 `NULL NOT IN (...)`이 NULL이라 검사를 지나쳤고, 표의 CHECK 제약이 대신 막았다. 009에서 안내 문장으로 거부하게 고쳤다.

### 그래프([zeek_ad/agent_graph.py](../zeek_ad/agent_graph.py))
- `analyst_review`(재개) → `apply_status` → END.
  - confirm이면 확인 중으로 바꾼다. dismiss면 확인 중을 거쳐 종료(오탐)로 바꾼다.
  - 바꿀 때마다 Slack 후속 알림을 기록한다(report_version `status:<상태>`, dry-run).
  - 대시보드에서 이미 바꿨으면 다시 바꾸지 않는다.
- 재개 명령은 `--analyst`가 필수다(이력에 누가 바꿨는지 남긴다).
- 경로 시험 5개(4개 → 5개) 통과. dismiss의 두 번 변경과 후속 알림, 대시보드가 먼저 바꾼 경우를 확인했다.

### 실행: eval-19(금요일 .14, 큐 9위, 정답상 공격 무관)
- LLM analyst_review, 판단 모델 analyst_review 0.34, 정책 send(필수) → 멈춤.
  - 평가 실행 때 LLM은 이 사건에 send를 골랐다. LLM 응답 변동이다.
- 사용자가 `dismiss`("도메인 컨트롤러 통신(DNS·DCE-RPC)이 평소보다 조금 많은 정상 업무로 판단")로 재개했다.
  - apply_status가 열림 → 확인 중 → 종료(false_positive)로 바꿨다. 이력 2행, Slack 후속 알림 2건("→ 확인 중", "→ 종료(오탐)")이 남았다.
- 이제 재개한 그래프가 결정만 기록하는 데서 끝나지 않는다. 저장된 상태를 이어받아 상태 변경과 후속 알림까지 한다(열셋째 작업의 판단에서 말한 이점).

## 열다섯째 작업: 분석가 대기 규칙과 템플릿 한국어화(2026-11-17)
- 분석가 대기는 판단 모델이 analyst_review일 때만 한다(Q49). LLM 의견은 send_decision에 기록만 한다. 경로 시험에 "LLM만 analyst_review면 대기하지 않음"을 더했다(그래프 시험 6개).
- 템플릿 보고서의 판단 한계 문장을 한국어(`LIMITS_KO`)로 바꿨다. LLM 입력의 notes는 영어 그대로다(LLM에 보내는 고정 설명).
  - 평가 동결(freeze.v1) 뒤의 변경이다. 평가 세트 결과 파일의 템플릿은 영어 문장 그대로 남아 있다. 동결 대상 `zeek_ad/llm_input.py`의 해시도 바뀌었다. 평가 결과를 다시 만들 일이 생기면 동결 시점 코드로 되돌려 돌린다.
- 전체 관련 시험 32개 통과.

## 열여섯째 작업: MLflow Tracing(가볍게, 2026-11-17, 설계 9.2절)
- 왜: 학습 기록(Tracking)이 아니라 운영 중 LLM 흐름의 실행 기록이다. LLM 응답 변동(같은 사건의 의견이 바뀜)과 지연 편차(23\~110초)를 사건 단위로 다시 찾아보기 위해서다.
- 방식([zeek_ad/agent_graph.py](../zeek_ad/agent_graph.py) `traced`, [scripts/run_agent_graph.py](../scripts/run_agent_graph.py) `traced_run`)
  - 그래프 실행 한 번 = trace 하나(루트 span `incident_flow.start`·`incident_flow.resume`, 종류 AGENT). 노드 하나 = span 하나(수집·rag는 RETRIEVER, 보고서·판단은 LLM, 나머지는 CHAIN).
  - span 속성은 노드가 만든 실행 기록 줄만 옮긴다: 지연, 사실 수, 검색 방법·문장·후보, 보고서 종류, 응답 모델 버전, 토큰(입력·출력·thinking), 시도 횟수, 오류, 판단과 확률, 전송 여부, 상태 변경.
  - 그래프 상태 전체(근거 요약의 실제 IP)는 넣지 않는다. 그래서 LangGraph 자동 기록(autolog)은 쓰지 않았다. 사건은 incident_id 대신 캡처·작업·큐 순위 태그로 찾는다.
  - interrupt는 오류가 아니므로 span을 정상으로 닫고(`zeekad.interrupted`) 다시 던진다. 재개는 별도 trace(`incident_flow.resume`)이고 같은 태그로 잇는다.
  - `--no-trace`로 끌 수 있다. 실험 이름 `zeekad-agent-traces`(MLflow 백엔드는 PostgreSQL mlflow DB).
- 실행: eval-13(금요일 .50 응답, 큐 3위, 포트스캔·SSH)
  - trace `tr-e0ec4bad34e111722849a65621933284`, 상태 OK, 총 16.5초. 노드 span 8개가 모두 루트 아래에 있다. 병렬 수집 세 노드도 같은 부모라서, LangGraph가 스레드로 돌려도 문맥이 이어진다.
  - write_report가 15.0초(토큰 입력 4,339·출력 923·thinking 1,120)로 대부분이다. LLM send, 판단 모델 send 0.69, 정책 send(필수).
  - trace JSON 전체(6,861자)에서 IP 형식 문자열 0개.
- 그래프 경로 시험 6개 통과(가짜 LLM 응답에 토큰 칸이 없어도 동작하게 고쳤다).
- 보는 법: `python scripts/mlflow_ui.py` → http://127.0.0.1:5000 → 실험 zeekad-agent-traces → Traces 탭.

## 열일곱째 작업: 데이터 계약 v2(2026-11-17)

- 이유: 단계 5b 결과 표(보고서·판단·Slack)는 원래 표라 대시보드 계정이 읽지 못했다. 대시보드가 읽을 뷰와 열 뜻을 정했다.
- [010_dashboard_v2.sql](../db/migrations/010_dashboard_v2.sql): 뷰 4개 추가(`incident_reports`, `send_decisions`, `slack_deliveries`, `slack_summaries`). jsonb 안의 자주 쓰는 값(검증 통과 여부, 응답 모델 버전, 토큰, 판단 모델 확률 등)을 열로 꺼냈다. LLM 원래 출력은 열지 않았다(검증 실패한 글일 수 있다).
- [data-contract-v2.md](data-contract-v2.md): 새 뷰 4개와 008의 상태 뷰 3개, 상태 변경 함수(`dashboard_rw`) 사용법. v1 뷰는 그대로다.
- 확인(`dashboard_ro`로 조회): 보고서 60행(LLM 58, 템플릿 2), 판단 60행, Slack 60행(사건 알림 58, 상태 알림 2), 일일 요약 8행. IP 형식이 나오는 열은 `incident_id`와 Slack 본문뿐이다(둘 다 사건 자산 H). worker 계정은 dashboard 뷰를 읽지 못한다(그대로).
- 알려진 빈칸 두 가지가 드러났다(Q50): 보고서의 사실 번호·가명을 풀 표가 없음, 분석가 검토를 대시보드에서 끝낼 방법이 없음.

### 이어서: 사실 목록과 가명표 저장(Q50 1번)
- [011_report_facts.sql](../db/migrations/011_report_facts.sql): `agent_report.facts`, `agent_report.pseudonyms` 열과 뷰 열 `zeekad_facts`, `zeekad_pseudonyms`(뷰 끝에 추가, 기존 열 그대로).
- `agent_inputs.pseudonym_map(evidence, nets)`: build_facts와 같은 순서로 가명표를 다시 계산한다. `save_report`가 두 열을 함께 쓴다(그래프·일반 함수 버전·적재 스크립트 모두).
- [tests/test_agent_inputs.py](../tests/test_agent_inputs.py): build_facts 안의 실제 가명표를 가로채 비교한다. 대표 연결이 상한(5개)을 넘는 경우 포함. 관련 시험 34개 통과.
- [scripts/backfill_report_facts.py](../scripts/backfill_report_facts.py): 기존 60건을 채웠다. 60건 모두 저장된 입력 파일이 있었고, 다시 계산한 사실 목록과 같았다. 보고서·사실에 나온 가명이 모두 가명표에 있었다. 사실 목록 속 IP 0개. 가명표 크기 2\~7.
- 예(eval-13): 주장 "외부 피어 X1과의 연결이 150941건" → F34 `top_peer_1 {peer: X1, connections: 150941}` → X1 = 172.16.0.1.
- Q50 2번(대시보드에서 검토 결정)은 배포 작업 때 근거 API에 경로를 더해 처리한다.
- 동결 해시 점검: `zeek_ad/llm_input.py`(한국어 템플릿 한계 문장, 열다섯째 작업에 기록)와 `scripts/build_agent_inputs.py`(입력 계산을 `agent_inputs.py`로 옮김, 계산 결과 60건 동일)가 동결 뒤 바뀌었다. 이번 작업은 두 파일을 고치지 않았다.

## 열여덟째 작업: Java 대시보드 brief를 데이터 계약 v2로 갱신(2026-11-17)

- [java-dashboard-agent-brief.md](java-dashboard-agent-brief.md) 2장의 "계획, 열 이름 미정"을 확정된 v2 내용으로 바꿨다: 보고서(사실 번호·가명 풀기), 세 의견 판단(confidence는 정확도 아님), Slack 기록(dry-run 표시), 상태·이력, 분석가 승인 대기(버튼은 근거 API 경로가 생기면 연결), 상태 변경 함수 호출법(MyBatis `#{}`), 알림 묶음은 아직 없음.
- 접속 표에 `dashboard_rw`를 넣고, NAS로 옮기면 주소가 바뀌니 설정값으로 받으라고 적었다. 3장 화면 목록의 "(단계 5 이후)"를 지웠다.
- 확인: `dashboard_rw`로 문서의 이름 붙인 인자 호출을 실행했다. 종료된 사건에 다시 종료를 보내면 `22023 허용되지 않는 상태 변경: closed → closed`로 거부되고 상태는 그대로다. `dashboard_rw`는 뷰·표를 읽지 못한다(42501). 그래서 읽기·쓰기 연결을 따로 둔다고 적었다.

## 열아홉째 작업: Java 대시보드 자체 DB(2026-11-17, Q51)

- 요청: Java 대시보드 AI가 사용자·역할·허용 캡처·세션·로그인 시도·감사 로그를 둘 별도 DB를 요청했다(사용자 전달). DB 이름 `zeekad_dashboard`, 소유 계정 `dashboard_app`, 비밀번호 환경 변수 `DASHBOARD_APP_PASSWORD`.
- 새 서버용: [init/01-roles-databases.sh](../deploy/postgres/init/01-roles-databases.sh)에 계정·DB·PUBLIC 접속 회수를 더했다. [compose.yaml](../deploy/compose.yaml), [.env.example](../deploy/.env.example), [zeek_ad/db.py](../zeek_ad/db.py)(권한 확인용 키)도 맞췄다.
- 지금 서버용: [scripts/add_dashboard_app.py](../scripts/add_dashboard_app.py). `deploy/.env`에 무작위 비밀번호를 덧붙이고(권한 600 유지, 값은 출력하지 않음) 계정·DB를 만든다. 여러 번 실행해도 된다.
- 확인:
  - `dashboard_app` → `zeekad_dashboard`: 접속, 표 만들기·지우기 가능. DB 소유자 `dashboard_app`, public 스키마 소유자 `pg_database_owner`(= DB 소유자)라 Flyway가 public에 표를 만들 수 있다.
  - `dashboard_app` → `zeekad`, `mlflow`: 거부("User does not have CONNECT privilege").
  - `dashboard_ro`, `dashboard_rw`, `zeekad_worker`, `zeekad_api`, `mlflow` → `zeekad_dashboard`: 모두 거부.
- [Java brief](java-dashboard-agent-brief.md) 접속 표와 4장 문장을 고쳤다.


## 스무째 작업: LangGraph 실습 노트북(2026-11-18, 사용자 요청)

- practice/05_langgraph_basics.ipynb(실습 노트북, 저장소에 없음): 노트북 01\~04와 같은 형식(셀마다 "코드 | 뜻" 표와 예상 결과). DB·API 키 없이 가짜 노드로 돈다.
- 다루는 것: State·reducer, fan-out/fan-in(리스트 엣지를 쓰는 이유: 갈래 길이가 다르면 따로 쓴 엣지는 merge가 두 번 돈다), 병렬 노드가 reducer 없는 키에 쓰면 나는 `InvalidUpdateError`, 조건 엣지와 반복 상한, `recursion_limit`(1.2.19 기본값 10,007), checkpointer·thread_id·`get_state_history`, interrupt·`Command(resume=...)`(재개하면 노드가 처음부터 다시 돈다 → 멱등 쓰기), 마지막으로 실제 `build_graph`의 구조와 코드 줄 대응표.
- 확인: `zeek-ad` 환경에서 코드 셀 15개를 IPython으로 차례로 실행해 모두 통과했고, 출력이 셀마다 적은 예상과 같다(병렬 수집 0.50초, 재개 후 노드 실행 2번·표 1행, checkpoint step -1\~8). 저장된 출력은 없다(사용자가 직접 실행한다).
