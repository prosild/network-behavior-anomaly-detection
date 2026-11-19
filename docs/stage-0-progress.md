# 단계 0 진행 기록

기록일: 2026-11-03, Asia/Seoul. 기준은 [최종 설계](../FINAL_PROJECT_DESIGN.md)와
[구현 체크리스트](../IMPLEMENTATION_CHECKLIST.md)다. 요청에 있던
`final-design-verification-request.md`는 없으며, 현재 체크리스트 파일명을 사용한다.
설계 변경이나 추가 설계 검토는 하지 않았다.

설계 질문·이의와 그 결과는 [설계 질문 기록](design-discussion-log.md)에 따로 남긴다.

## 시작 시 상태

| 구분 | 확인한 상태 |
| --- | --- |
| 설계 | 확정. 자산 제외, 역할, 시간창, 월요일 분할, 에피소드·평가 규칙은 이미 정의됨 |
| 기존 데이터 검증 | 체크리스트에 원본 21개 로컬 사본 간 SHA-256 일치, CSV 품질, 시간 범위, 월요일 창 수가 기록돼 있음. 이번에 반복 계산하지 않음 |
| 프로젝트 구현 | 시작 시 프로젝트에는 설계 문서 3개와 원본 폴더만 있었음. 이번 입력 검사 스크립트가 첫 구현 |
| 모델 | 프로젝트 모델 학습은 미시작. 과거 통계 경험분포 탐색은 설계 12.3절의 노출 이력으로 유지 |
| 원본 실재 | PCAP 5개, TrafficLabelling CSV 8개, MachineLearningCVE CSV 8개. 합계 54,521,141,013 bytes |
| 기타 입력 | `:Zone.Identifier`, 개선 라벨, 새 Zeek 로그는 현재 원본 폴더에 없음 |
| 과거 임시 자료 | 체크리스트 2.1절의 scratchpad가 존재함. `an1.py`~`an7.py`, `pcapng_order.py`, `zs`, `out`, `conn.parquet`의 존재만 확인 |
| Git | `.git` 경로는 있지만 `git status --short`는 저장소가 아니라고 실패. 초기화·커밋은 하지 않음 |

## 첫 작업: 입력 manifest와 읽기 전용 목록 검사

체크리스트 V1의 입력→실행→출력 계보 중 **입력 목록 부분**을 구현했다.
전체 V1이나 단계 0 완료는 아니다.

- [입력 manifest](../manifests/cic-ids-2017.inputs.v1.json): 상대 경로, 바이트 크기, 기존 SHA-256을 보존한다.
- SHA-256은 체크리스트 5절에서 그대로 옮겼다. 전사한 21개 값의 일치를 확인했으며 원본 해시는 재계산하지 않았다. 공식 배포본 인증으로 해석하지 않는다.
- 파일별 크기는 이번 `stat()` 조회값이다. 합계가 기존 문서와 일치하는지 확인했다.
- [검사 스크립트](../scripts/check_inputs.py): Python 표준 라이브러리만 사용한다. 추가 설치가 필요 없다.
- 원본은 `CIC-IDS-2017/`, 향후 생성 산출물은 별도 `outputs/`를 사용한다. 두 경로를 `.gitignore`에 넣었다. `.gitignore`는 Git 추적 제외 규칙이며 파일 쓰기를 막는 권한 설정은 아니다.

프로젝트 루트에서 실행:

```bash
python3 scripts/check_inputs.py
```

다른 입력 사본은 `--input-root /path/to/CIC-IDS-2017`로 지정한다.
기본 경로는 실행 위치가 아니라 스크립트가 속한 프로젝트를 기준으로 계산한다.
작은 샘플 검증에는 `--manifest /path/to/manifest.json`을 사용할 수 있다.

동작 순서:

1. JSON manifest에서 기대하는 파일 경로와 크기를 읽는다.
2. 입력 폴더의 파일 목록과 크기를 파일시스템 메타데이터로 조회한다.
3. 누락·추가·크기 차이를 비교해 JSON을 표준 출력에 기록한다.
4. 일치하면 종료 코드 0, 불일치하면 1, 입력 디렉터리가 없으면 2를 반환한다.

입력 PCAP·CSV 내용은 읽거나 변경하지 않는다. 같은 크기의 내용 변경은 검출하지 못한다.
출력의 `sha256_recomputed: false`가 이 검사의 범위를 표시한다.
새 입력을 받거나 내용 변경이 의심되면 별도의 해시 검증이 필요하다.

실행 결과: `passed`, 21개, 54,521,141,013 bytes, 누락·추가·크기 불일치 모두 0.
사용자도 직접 실행해 같은 결과를 확인했다. 전달받은 실행 시각은
`2026-11-03T02:48:00.954578+00:00`이며 해시 재계산은 하지 않았다.
임시 소형 파일로 정상 입력, 크기 변경, 파일 누락, 예상 밖 파일, 없는 입력 디렉터리를
확인했다. 다른 작업 디렉터리에서도 기본 입력 경로를 찾았다. 실패 사례를 만들기 위해
실제 원본을 변경하지 않았다.

## 두 번째 작업: 내부 자산 판정 규칙

최종 설계 3.2절과 2.1절 C1의 자산 규칙을 설정과 작은 주소 예제로 옮겼다.
규칙 자체는 바꾸지 않았다.

- [자산 설정](../configs/assets.cic-ids-2017.v1.json): 내부 대역 `192.168.10.0/24`와 규칙 출처.
- [판정 함수](../zeek_ad/assets.py): 표준 라이브러리 `ipaddress`만 사용한다.
  - `is_scored_asset`: 대역 안의 주소이면서 네트워크(`.0`)·브로드캐스트(`.255`) 주소가 아니면 점수화 대상이다. IP가 아닌 값은 `ValueError`로 드러낸다.
  - `role_observations`: 연결 하나가 만드는 `(asset_id, role)` 관측을 출발·수신 쪽에서 따로 판정한다. 연결 레코드를 거르지 않는다.
- [주소 예제](../tests/test_assets.py): 8개.
  - `.1`·`.3`·`.50`·`.254`는 호스트로 점수화한다.
  - `.0`·`.255`, `172.16.0.1`, 멀티캐스트, `192.168.100.5`, IPv6는 점수화하지 않는다.
  - 내부 간 연결은 두 역할을 모두 만든다. `.5 → .255`는 출발 역할만, `172.16.0.1 → .50`은 수신 역할만 만든다.

과거 스크립트는 `startswith('192.168.10.')` 문자열 접두사로 내부 주소를 판정했다.
예: an7.py(로컬 백업, 저장소에 없음) 5행. 이 방식에서는 `.255`가 수신 자산이 된다.
판정만 과거 방식으로 임시 교체해 돌리면 3개 테스트가 실패했다.
실패한 테스트는 `.0`·`.255` 제외, 브로드캐스트 연결의 출발 역할만 유지, 잘못된 값의 오류 처리다.
이는 테스트가 과거 오류를 검출한다는 확인이다. 이 교체는 파일을 수정하지 않고 실행 중에만 적용했다.

프로젝트 루트에서 실행:

```bash
python3 -m unittest tests.test_assets -v
```

실행 결과: 8개 모두 통과. 사용자도 2026-11-03에 직접 실행해 같은 결과를 확인했다.
실제 Zeek 로그에 적용하거나 창 수(328·77 등)를 재산출하지는 않았다. 그 대조는 단계 2(V3)에서 한다.
`local_orig/local_resp`와의 일치 검사도 아직 하지 않았다. 이 검사는 Zeek 로그를 읽는 단계에서 한다.

## 세 번째 작업: 5분 창 배정과 학습/보류 분할

최종 설계 4.2절과 6.1절의 창·분할 규칙을 설정과 작은 시각 예제로 옮겼다.
날짜별 경계 시각은 코드에 넣지 않았다. 코드는 일반 규칙에서 경계를 계산한다.

- [시간 설정](../configs/time-windows.v1.json): `window_seconds=300`, `split_fraction=0.8`, 배정 필드 `_write_ts`.
- [창·분할 함수](../zeek_ad/windows.py):
  - `window_start`: `floor(ts / 300) * 300`. Unix epoch에 맞추고 창은 `[start, end)`다.
  - `fraction_cutoff`: 끝난 캡처의 최소·최대 시각 사이 80% 지점. 오프라인 전용이다.
  - `assign_split`: cutoff를 인자로 받는다. 실시간 운영은 정한 학습 종료 시각을 넘기면 된다.
- [시각 예제](../tests/test_windows.py): 7개.
  - 창 경계 판정.
  - 가짜 캡처에서의 분할.
  - 월요일 대조: 학습 `[12:00, 18:20)`, 제외 `[18:20, 18:25)`, 보류 `[18:25, 20:00)`.
  - 창 크기를 바꿔도 같은 규칙이 동작하는지 확인. 1분 창 비교 실험은 아니다.

**구현 중 정한 경계 규칙:** 제외하는 창은 `start < cutoff < end`인 창, 즉 cutoff 앞뒤 데이터가 섞인 창이다.
- 처음 구현은 설계 문구 "포함하는 창"을 `[start, end)` 포함으로 읽었다. 그래서 cutoff가 창 시작과 같아도 그 창을 제외했다.
- 그 창에는 cutoff 이후 데이터만 있으므로 학습·보류가 섞이지 않는다. 운영에서 cutoff를 창 경계에 맞추면 깨끗한 창 하나를 이유 없이 버리게 된다.
- 그래서 `start >= cutoff`를 보류로 바꿨다. 체크리스트 5절의 "보류는 `window_start >= 18:25`"와도 맞는다.
- 월요일 cutoff는 창 경계가 아니므로 기존 구간과 기대 행 수는 바뀌지 않는다.

**분할 경계 창의 점수 처리(단계 3에서 구현):** `split_boundary` 창은 학습과 임계값 계산에서 빼지만 점수는 계산해 저장하고 표시한다.
- 이 창의 이상 여부를 숨기지 않기 위해서다.
- 이 제외는 월요일 학습·임계값 산출에만 쓴다. 화~금 평가와 운영의 점수화 대상에는 분할 경계 창이 없다.
- `capture_edge` 창은 설계 4.3절을 따른다. 주 점수 비교에서 제외하되, 그 구간의 공격 에피소드는 정답 분모에 남기고 경계 영향을 표시한다.

5분은 사전 기본값으로 고정한다. 창 크기 비교는 설계 6.2절의 선택 실험이며, 이번 구축 범위에서는 하지 않는다.

실행 결과: 시간창·자산 테스트 15개 통과. 사용자가 2026-11-03에 직접 실행해 확인했다.
이후 경계 규칙 변경과 주석 한글화를 반영해 Claude와 사용자가 다시 실행했고 15개 모두 통과했다.
실제 로그의 창 수 재산출은 단계 2(V3)에서 한다.

## 네 번째 작업: 정답 에피소드 기록 형식과 분모 계산

최종 설계 5.1절과 5.3절의 정답 단위·분모 규칙을 기록 형식과 작은 가짜 예제로 옮겼다.

- [에피소드 형식](../zeek_ad/episodes.py):
  - `Observation`: 캡처·자산·역할·시간 범위. 역할 값은 [assets.py](../zeek_ad/assets.py)의 `ROLES`를 함께 쓴다.
  - `Episode`: ID·시나리오·상태·판단 이유·관측 목록.
  - 생성 시 상태 값, 판단 이유 누락, 빈 관측, 잘못된 역할, 시간 범위 역전을 거부한다.
- 세는 규칙:
  - `daily_denominator`: 그 캡처에 관측이 있는 `confirmed` 에피소드. 자산·역할이 여러 개여도 1개로 센다.
  - `unique_confirmed`: 전체 고유 수. 일별 분모의 합과 구분한다.
  - `status_counts`: 분모에서 빠진 `uncertain`·`unsupported`도 보고한다.
  - 세 함수 모두 에피소드 ID가 중복되면 오류를 낸다.
- [예제](../tests/test_episodes.py): 가짜 에피소드 4개와 잘못된 기록 5종. 실제 CIC 정답표가 아니다.

하지 않은 것:
- 에피소드 분할·병합 판단: 단계 1에서 근거를 보며 하고, 에피소드마다 이유를 남긴다.
- 나머지 기록 필드: 선택 조건·버전, 근거 참조, 라벨 출처·불일치, 시도/성공 구분은 단계 1에서 추가한다.
- 실제 정답표 작성: 점수를 보기 전에 동결해야 하므로 지금 하지 않는다.

실행 결과: 전체 테스트 20개 통과. 사용자가 2026-11-03에 직접 확인했다.
이후 `ROLES` 상수를 `assets.py`로 옮겼고 Claude가 다시 실행해 20개 통과를 확인했다.

## 다섯 번째 작업: 실행 환경 고정 (진행 중)

사용자가 익숙한 conda로 프로젝트 전용 환경을 만든다. venv는 쓰지 않는다.
- conda가 맡는 것: Python, Java. Java를 환경 안에 두면 Spark가 쓰는 Java 버전이 시스템과 무관하게 고정된다.
- pip가 맡는 것: 나머지 Python 패키지. 같은 패키지를 conda와 pip 양쪽으로 설치하지 않는다.
- 채널은 `conda-forge`만 쓴다.

1단계, 환경 생성. 사용자가 2026-11-03에 실행했다.

```bash
conda create -n zeek-ad -c conda-forge --override-channels python=3.13 openjdk=21 -y
```

| 항목 | 결과 |
| --- | --- |
| Python | 3.13.18, `/home/prosild/anaconda3/envs/zeek-ad/bin/python` |
| Java | OpenJDK 21.0.10. conda-forge 빌드라 버전에 `internal`이 붙는다 |
| `JAVA_HOME` | `/home/prosild/anaconda3/envs/zeek-ad/lib/jvm` |

2단계, PySpark. 사용자가 2026-11-03에 실행했다.
- 설치: `python -m pip install pyspark==4.3.0`. 함께 설치된 의존성은 `py4j-0.10.9.9`.
- 확인: `local[2]`에서 `spark.range(5).count()`를 실행해 `spark 4.3.0`, `count 5`가 나왔다. Java 21에서 정상 동작한다.
- 출력된 경고 세 가지와 해석:

| 경고 | 해석 |
| --- | --- |
| `Using incubator modules: jdk.incubator.vector` | Spark가 Java의 실험적 벡터 연산 기능을 쓴다는 안내. 문제없음 |
| hostname이 loopback `127.0.1.1`로 해석돼 `10.255.255.254`를 대신 사용 | WSL 네트워크 설정 때문이다. 로컬 실행에는 문제없지만, 바인딩 주소를 고정하려고 `SPARK_LOCAL_IP=127.0.0.1`을 환경 변수로 둔다 |
| `NativeCodeLoader: Unable to load native-hadoop library` | Hadoop 네이티브 라이브러리가 없어 Java 구현을 쓴다는 안내. 로컬 Parquet 처리에는 문제없음 |

설계 문서의 Spark 링크는 4.1.2 문서다. 구현 기준 버전은 4.3.0이다.

3단계, Spark 주소 고정과 MLflow. 사용자가 2026-11-03에 실행했다.
- `conda env config vars set SPARK_LOCAL_IP=127.0.0.1`. 환경을 다시 활성화한 뒤 `127.0.0.1`을 확인했다.
- `python -m pip install mlflow==3.17.2`. 불러오기 결과는 `mlflow 3.17.2`, `pyspark 4.3.0`이다.
- `python -m pip check`: `No broken requirements found.`
- 실험 기록과 PostgreSQL 연결은 단계 3에서 한다.

GPU 관측(Claude, 2026-11-03): NVIDIA GeForce RTX 3080 12GB, WSL에서 `nvidia-smi`가 CUDA 13.3을 보고한다.

4단계, PyTorch. 진행 중이다.
- **선택: GPU용.** Claude는 CPU용을 권했지만, 사용자가 GPU를 쓰려고 일부러 CUDA용 `torch 2.15.0+cu132`를 설치했다.
- **현상:** `import torch`와 CPU 연산은 정상이었다. `torch.cuda.is_available()`에서 Segmentation fault가 났다.
- **원인(Claude 확인):**
  - `LD_DEBUG=libs`로 보면, 충돌 직전에 WSL의 `libcuda`가 `/lib/x86_64-linux-gnu/libnvidia-ptxjitcompiler.so.1`을 읽는다.
  - 이 파일은 Ubuntu 패키지 `libnvidia-compute-580`(580.178)의 Linux용 드라이버 라이브러리다. Windows 드라이버(610.x)의 WSL 라이브러리와 버전이 맞지 않는다.
  - 이 패키지는 Ubuntu `nvidia-cuda-toolkit`·`nvidia-cudnn`의 의존성으로 설치돼 있다. `libnvidia-compute-535`도 함께 있다.
  - `cuda-bindings`로 `cuInit`만 호출하면 정상이었다.
- **해결 방식: 프로젝트 환경에서만 처리한다.**
  - conda 활성화 스크립트가 WSL 드라이버 폴더(`/usr/lib/wsl/drivers/*/`)를 `LD_LIBRARY_PATH` 앞에 넣는다.
  - 폴더 이름은 Windows 드라이버 업데이트로 바뀌므로 활성화할 때마다 찾는다.
  - 스크립트는 [env/conda/](../env/conda/)에 있다.
  - 이 방식으로 RTX 3080 인식과 GPU 행렬 연산을 확인했다(Claude).
- **다른 환경과의 비교(Claude 확인):** 같은 WSL의 다른 conda 환경 6개는 `torch.cuda.is_available()`가 모두 `True`다.
  - 해당 torch: 1.12.0, 2.2.2+cu121, 2.8.0+cu128, 2.12.x+cu126, 2.14.1+cu130.
  - 2.14.1+cu130은 초기화 때 `libnvidia-ptxjitcompiler`를 읽지 않는다. 2.15.0+cu132는 읽는다. 두 빌드 모두 `sm_86`(RTX 3080)을 포함한다.
  - 즉 잘못된 580 라이브러리는 전부터 있었지만, 이번 빌드가 처음으로 그 파일을 읽어서 문제가 드러났다. 설치가 덜 된 것이 아니다. 왜 새 빌드만 읽는지는 확인하지 않았다.
  - 대안: 2.14.1+cu130으로 낮추면 우회 스크립트가 필요 없다. 하지만 시스템의 불일치는 그대로 남는다.
- **적용 결과(사용자, 2026-11-03, 방법 A):** 스크립트를 `$CONDA_PREFIX/etc/conda/`에 복사하고 환경을 다시 활성화했다.
  - `torch 2.15.0+cu132`, `cuda True NVIDIA GeForce RTX 3080`, seed 42 난수 합 `1.653`.
  - Spark `count 5`. 라이브러리 경로 변경이 Spark에 영향을 주지 않았다.
- **이미 설치된 데이터 라이브러리:** MLflow 의존성으로 numpy 2.5.4, pandas 3.1.0, pyarrow 25.0.1, scikit-learn 1.9.1, SQLAlchemy 2.1.6이 설치돼 있다. 따로 설치하지 않고 의존성 고정 때 함께 기록한다.
- **CUDA UMD 13.3과의 관계:** `nvidia-smi`의 CUDA UMD 13.3은 Windows 드라이버가 지원하는 최대 CUDA 버전이다. cu132 빌드(13.2)는 그 범위 안이다. Segmentation fault는 CUDA 버전 문제가 아니라 잘못된 580 라이브러리를 읽은 문제였다.
- **시스템 패키지는 지우지 않는다.** Ubuntu NVIDIA 패키지를 지우면 다른 프로젝트가 쓰는 Ubuntu CUDA toolkit도 함께 지워질 수 있다. 시스템 정리는 사용자 판단으로 남긴다.
- **재현성(단계 3에서 처리):** GPU 연산은 일부가 비결정적이다. Transformer 학습에서 결정적 알고리즘 설정과 seed를 기록하고, 같은 설정의 재실행 결과를 비교한다.

5단계, AI 계층 패키지. 사용자가 2026-11-03에 실행했다.
- 설치: langgraph 1.2.19(의존성으로 langchain-core 1.7.4), psycopg[binary] 3.3.7, pgvector 0.5.1, sentence-transformers 6.2.0, rank-bm25 0.2.2.
- torch는 바뀌지 않았고 `cuda True`다. `pip check`는 충돌 없음.
- `importlib.metadata`로 읽은 torch 버전은 `2.15.0`이다. PyPI 기본 CUDA 빌드는 패키지 메타데이터에 `+cu132`를 붙이지 않는다. `torch.__version__`은 `2.15.0+cu132`를 보인다.
- 설치하지 않은 것: LLM 공급자 SDK, Jev·Slack 연동, LangChain pgvector 연동, 임베딩 모델 가중치. 단계 5에서 정한다.

6단계, 의존성 고정. 완료.
- [requirements.txt](../requirements.txt): 직접 쓰는 패키지 12개의 정확한 버전.
- [environment.yml](../environment.yml): conda의 Python 3.13.18·OpenJDK 21.0.10·pip 26.2.2, `SPARK_LOCAL_IP`, 그리고 pip 잠금 파일 참조.
- [requirements.lock.txt](../requirements.lock.txt): 사용자가 2026-11-03에 `pip freeze`로 만들었다. 157줄.
  - Claude가 확인했다: 직접 패키지 12개 버전이 모두 `requirements.txt`와 일치하고, `file://` 같은 로컬 경로 항목이 없다.
  - NVIDIA·CUDA 관련 항목은 18개다.
- 재현 시험(새 환경을 이 파일로 만들어 비교)은 하지 않았다. 단계 1에서 한다.

**환경 작업 결과:** 단계 1~3에 필요한 Python 쪽 환경을 고정했다. Zeek 실행 환경(Docker 이미지 digest 고정과 작은 PCAP 실행)은 단계 1의 첫 작업이다.

## 현재 환경 관측

- Python 3.13.9 (`/home/prosild/anaconda3/bin/python3`), Java OpenJDK 21.0.12.1.
- CPU 논리 코어·affinity 모두 12개. `/proc/meminfo`의 전체 약 66.73 GiB, 가용 약 63.62 GiB.
- 프로젝트 파일시스템 여유 737,889,071,104 bytes, 약 687.21 GiB. 순간 관측값이다.
- `docker`, `capinfos`, `editcap` 실행 파일이 PATH에 있다. Docker daemon·이미지 실행은 아직 확인하지 않았다.
- `zeek` 실행 파일은 PATH에 없고, 현재 Python에 `pyspark`·`mlflow`는 없다.
- 현재 Python에는 pandas 2.3.3, pyarrow 21.0.0, scikit-learn 1.7.2가 있다. 프로젝트 의존성 확정값은 아니다.
- 표준 cgroup v2의 `memory.max`·`cpu.max` 파일이 없어 실행별 자원 한도는 확인하지 못했다. 위 호스트 수치를 할당 보장량으로 해석하지 않는다.

## 단계 0에 남은 일과 다음 작은 작업

1. **자료 보존 완료, 실행 재현 미완료:** 과거 검증 자료(로컬 백업, 저장소에 없음)에 스크립트 8개·Zeek 설정 1개를 수정 없이 보존했다. 9개 파일 총 27,540 bytes의 원본·복사본 SHA-256 일치를 확인했다. 기존 입력 manifest와 5일 conn 위치·기존 해시, 보고된 실행 설정을 연결했다. 큰 로그는 복사하거나 다시 해시하지 않았다. conn 외 로그의 해시·실행 연결, 같은 설정 재실행은 여전히 미완료다. 따라서 V1 전체 완료가 아니다.
2. **완료:** 내부 자산 판정, 시간창·분할, 정답 에피소드 기록 형식·분모 규칙을 위 두~네 번째 작업으로 옮겼다. 에피소드의 실제 분할·병합 판단과 ID 형식은 단계 1에서 근거를 보며 정한다.
3. **초안 작성:** [관측 의미](observation-meaning.md)에 공격 후보와 정상 비교의 관측 의미·근거 수준·불확실성을 기록했다.
   - 공격 후보: 수요일 Slowloris.
   - 정상 비교: 월요일 `.50`의 responder 활동.
   - 새 데이터는 열람하지 않았다. 실제 선택 조건과 대표 근거 검토는 단계 1로 이어진다.
   - 사용자가 2026-11-03에 내용을 확인했다. 확인 질문은 탐지 창 지연 이유와 NAT 활동 부재의 위험이었다.
4. **확인·기록:** [데이터 이용 조건](data-usage-terms.md)에 정리했다.
   - CIC 공식 FAQ상 재배포·재게시가 가능하다. 조건은 데이터셋과 지정 논문의 인용이다.
   - 원본은 용량과 재현성 때문에 Git에 넣지 않는다.
   - 개선 라벨: 사용자가 `CICIDS2017_improved/`에 CSV 5개(1,152,270,765 bytes)로 받아 두었다. Claude가 SHA-256을 계산해 [manifest](../manifests/cicids2017-improved.inputs.v1.json)에 기록했고, 목록 검사도 통과했다.
     - 확인한 구조: 91열, 마지막 열은 `Label`·`Attempted Category`.
     - 내용 분석은 단계 1에서 한다.
   - 사용자가 2026-11-03에 확인했다.
5. **완료:** 실행 환경을 conda `zeek-ad`로 고정했다. 위 다섯 번째 작업 참고. Zeek 실행 환경은 단계 1에서 고정한다.

시간 의미·EOF·`-C` 영향의 실험은 단계 1, Spark 품질 집계는 단계 2,
모델·MLflow 학습은 단계 3의 작업이다. 이번에 완료된 것으로 표시하지 않는다.

단계 3 결과 해석 때 함께 다룰 한계(사용자 요청, 2026-11-03):
- DB 덤프 같은 대용량 전송은 conn의 자산 관점 송수신 바이트로 보인다. 하지만 내용을 몰라 덤프·백업·대량 조회를 구분하지 못한다.
- 주 모델은 호스트별 기준선이 없는 공통 모델이다. 평소에도 대용량을 보내는 자산의 이상은 놓칠 수 있다.
- CIC-IDS-2017에는 이 시나리오가 없어 검증할 수 없다.
- 이 내용은 한계 기술과 후속 버전 후보로 기록한다.

모델 범위 확인(사용자 결정, 2026-11-03):
- 통계 기준선 + Isolation Forest가 주 기준선이다. 지도학습은 넣지 않는다.
- 그래프 모델은 별도 프로젝트로 진행한다.
- 이후 이 아키텍처에 근거를 제공하는 하위 모델로 연동하는 것은 핵심 완성본 이후의 후보로 둔다.
- 같은 날 이후 변경: [DD-002](design-decisions/DD-002-transformer-langgraph-rag.md)에 따라 다음을 필수로 포함한다.
  - 자기지도 Transformer 비교 모델(단계 3).
  - pgvector RAG와 LangGraph 흐름(단계 5).
- Slack 보고와 Jev 전송 판단은 [DD-001](design-decisions/DD-001-slack-delivery-jev-gate.md)을 따른다.

학습 확인 포인트: “파일 경로·크기 검사를 통과했다”와 “현재 파일의 SHA-256을 검증했다”의
차이, 원본과 출력 경로를 나누는 이유, 종료 코드로 후속 실행을 제어하는 방법을 설명할 수 있어야 한다.

## 단계 0 완료 판정 (2026-11-03)

최종 설계 10절의 단계 0 완료 기준과 대조한다.

| 기준 | 상태 |
| --- | --- |
| 자산 제외 규칙 고정 | 완료. 설정·코드·테스트 |
| 에피소드 분할·병합 규칙 고정 | 기록 형식과 세는 규칙은 완료. 분할·병합 기준은 설계 5.1절을 따르며, 개별 판단은 단계 1에서 근거와 함께 기록한다 |
| 공격 후보 하나·정상 비교 하나의 관측 의미 | 완료. 사용자 확인 |
| 입력 경로·버전 기록 | 완료. 원본 manifest, 개선 라벨 manifest |
| 라이선스 | 완료. 사용자 확인 |
| 분할 기록 | 완료. 시간창·분할 코드와 월요일 대조 테스트 |
| 환경 자원 확인 | 완료. conda `zeek-ad` 고정 |

단계 1로 넘기는 일:
- Zeek Docker 이미지 digest 고정과 작은 PCAP 실행.
- 같은 설정의 재실행 재현(V1).
- `_write_ts`·EOF·`-C` 영향 확인(V2).
- 정답 후보의 근거 검토와 에피소드 ID 확정(V4).
- 새 환경을 잠금 파일로 다시 만들어 보는 재현 시험.
