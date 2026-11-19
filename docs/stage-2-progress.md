# 단계 2 진행 기록

시작일: 2026-11-03, Asia/Seoul. 기준은 [최종 설계](../FINAL_PROJECT_DESIGN.md) 7절과 10절 단계 2, [체크리스트](../IMPLEMENTATION_CHECKLIST.md) V3다. 입력은 단계 1에서 만든 Bronze 로그 `outputs/zeek/<요일>/run-01/`이다.

계층:
- Bronze: Zeek JSON 원문과 실행 manifest. 고치지 않는다.
- Silver: 명시적 스키마, 열 이름 정리, 결측 보존, 원본 행 번호, 품질 오류 격리. 한 행이 연결 하나다.
- Gold: 자산·역할·5분 창별 특징. 한 행이 창 하나다.

## 첫 작업: Bronze conn.log를 명시적 스키마로 읽기

- [zeek_ad/conn_schema.py](../zeek_ad/conn_schema.py): Zeek 8.0.10 conn 필드 22개와 `_corrupt_record`.
  - 필드 목록은 5일 로그 전체에서 실제로 나온 키로 정했다. Claude가 조사했다.
  - 5개 필드는 행에 따라 없다: `duration`, `orig_bytes`, `resp_bytes`, `history`, `service`.
- **시각 타입:** double로 읽는다.
  - Zeek JSON의 시각은 double의 최단 표현으로 찍힌다. 그래서 소수 자릿수가 1~7자리로 다르다. 예: `1499083322.5595331`.
  - Decimal(16,6)로 읽으면 7자리 값이 바뀐다(월요일 `ts` 430개, `_write_ts` 410개).
- **바이트·패킷 타입:** long. 긴 연결에서 int 범위를 넘을 수 있다.
- [scripts/inspect_conn.py](../scripts/inspect_conn.py): 읽기 전용 확인 스크립트.
  - 행 수와 깨진 행을 센다.
  - 스키마에 없는 필드를 찾는다. 명시적 스키마는 모르는 필드를 조용히 버리기 때문이다.
  - 결측(null)과 0을 따로 센다.
- **환경 조정:** PySpark 4.3.0이 pandas 3에 대해 "아직 완전히 지원하지 않는다"는 FutureWarning을 냈다.
  - pandas를 2.3.3으로 낮췄다. 함께 pytz·tzdata 2026.6이 설치됐다.
  - `requirements.txt`와 잠금 파일(159줄)을 갱신했다. `pip check` 통과, 경고 사라짐(Claude 확인).

월요일 결과(사용자 실행, 2026-11-03):

| 항목 | 값 |
| --- | --- |
| 행 | 375,432 |
| 깨진 행 | 0 |
| 스키마에 없는 필드 | 없음 |
| duration | 결측 6,724, 0인 값 0 |
| orig_bytes | 결측 6,724, 0인 값 10,523 |
| resp_bytes | 결측 6,724, 0인 값 13,312 |
| service | 결측 19,475 |
| history | 결측 172 |

- duration 결측 6,724행, 실제 0 없음은 과거 측정과 같다.
- 바이트의 0은 실제로 0바이트를 보낸 연결이다. 결측과 구분된다. 과거 Parquet는 둘을 섞었다(체크리스트 2.1절).

## 개념 실습: PySpark 기초 노트북

Silver 저장을 실행하기 전에, 사용자가 Zeek·Docker·PySpark·Parquet의 동작부터 이해하기로 했다(2026-11-03).
- practice/01_spark_basics.ipynb(실습 노트북, 저장소에 없음): 7개 주제를 셀마다 설명과 함께 다룬다. SparkSession, 읽기 계획과 스키마, 지연 실행(변환과 동작), groupBy와 Spark SQL, 파티션과 `explain()`, Parquet 저장·재읽기.
- `practice/`는 학습용이라 Git에서 제외한다. 실습 출력은 `outputs/practice/`에 쓴다.
- 노트북을 `zeek-ad` 커널로 실행하려고 `ipykernel`을 개발 도구로 추가했다.
- Claude가 코드 셀을 순서대로 실행해 확인했다: 코어 12, TCP 1,684행, 샘플 파티션 1, 월요일 파티션 12, Parquet 재읽기 1,684행.

## 패키지 설치 방식 질문

사용자가 노트북의 `sys.path.insert` 코드가 일반적인 방식인지 물었다(2026-11-03).
- Claude는 `pyproject.toml`과 editable 설치(`pip install -e .`)로 바꿨다.
- 사용자는 질문만 한 것이고 바꿀 필요가 없다고 했다. 그래서 원래대로 되돌렸다. `sys.path` 방식을 유지한다.
- **사고와 복구(2026-11-03):** 설치 명령이 `zeek-ad`가 아닌 anaconda `base` 환경에서 실행됐다.
  - 증상: base에서 `spyder-kernels 3.1.1`과 ipykernel 7.4.0이 충돌했다.
  - base에서 바뀐 패키지: ipykernel 6.31.0→7.4.0, jupyter_client 8.6.3→8.10.0, tornado 6.5.1→6.6, nest-asyncio2 1.7.4(새로 설치), zeek-ad 0.1.0(editable).
  - 잠금 파일이 base 환경의 목록(385줄, pyspark 없음)으로 덮어써졌다. Claude가 `zeek-ad` 환경에서 `pip freeze --exclude-editable`로 다시 만들었다. 결과는 182줄, `pip check` 통과.
  - base 복구는 사용자가 실행한다.

## 클러스터 실행 결정

사용자가 Spark를 실무 환경처럼 배우려고 Standalone 클러스터 실행을 추가했다(2026-11-04, [DD-004](design-decisions/DD-004-spark-standalone-cluster.md)).
- local에서 Silver·Gold를 먼저 완성한 뒤 진행한다.
- 그때 코드의 `.master("local[*]")` 고정을 빼고 실행 명령에서 정하게 바꾼다.

## 두 번째 작업: Silver 저장

- [zeek_ad/silver_conn.py](../zeek_ad/silver_conn.py): Bronze 한 줄마다 원본 행 번호를 붙이고 JSON을 해석한다.
  - `ts`·`_write_ts`가 없거나 해석에 실패한 행은 원문과 함께 격리한다.
  - 점이 든 이름을 바꾸고(`id.orig_h`→`orig_h`, `_write_ts`→`write_ts`), `eof_candidate`를 표시한다.
- [scripts/build_silver_conn.py](../scripts/build_silver_conn.py): `conn_v1/conn/capture_id=<ID>/`와 `conn_v1/quarantine/capture_id=<ID>/`에 쓴다. 이미 있으면 덮어쓰지 않는다.

월요일 첫 실행(사용자, 2026-11-04): Silver 375,432행, 격리 0, `eof_candidate` 292, 행 번호 1~375,432가 모두 다름. `processing_run_id=62bc2db42bafb271`, 21MB. 점이 든 열 이름이 없는 것을 확인했다.

### Silver manifest 추가

설계 7절 "임시 위치에 완성한 뒤 검증된 manifest를 게시한다. 부분 결과를 완료 결과로 읽지 않는다"를 구현했다(2026-11-04).
- 저장한 Parquet를 다시 읽어 검증한다. Silver+격리 행 수가 Zeek 실행 manifest의 conn 행 수와 같은지 본다. 두 쪽의 원본 행 번호를 합치면 1..N이 정확히 한 번씩 나오는지도 본다.
- 검증을 통과해야 `conn_v1/_manifests/<capture_id>.json`을 쓴다. 임시 파일에 쓴 뒤 이름을 바꾼다.
- manifest 내용: 입력(실행 manifest·conn.log 해시), 코드 파일 3개의 해시, Spark·Python 버전, 행 수, 검사 결과, 출력 Parquet 파일 해시.
- Git 저장소가 아니어서, 코드 버전은 파일 해시로 남긴다.
- Claude 확인(임시 폴더): 샘플 8,758행에서 검사 통과와 manifest 생성, 재실행 거부를 확인했다. 행 수를 일부러 틀린 실행 manifest로는 검사가 실패하고 manifest가 생기지 않았다(종료 코드 1).
- 월요일 첫 결과는 manifest 없이 만들어졌으므로 지우고 5일을 새로 만든다.

### 5일 Silver 결과(사용자 실행, 2026-11-05)

| capture_id | Bronze=Silver 행 | 격리 | eof_candidate | processing_run_id |
| --- | --- | --- | --- | --- |
| cic17-mon | 375,432 | 0 | 292 | 62bc2db42bafb271 |
| cic17-tue | 323,342 | 0 | 121 | 56acdda456b3d646 |
| cic17-wed | 509,362 | 0 | 7 | 89f4d87beb255ff4 |
| cic17-thu | 363,788 | 0 | 30 | 2ff88c56f0d1b48c |
| cic17-fri | 547,353 | 0 | 57 | 20c73af95ee60112 |

- 합계 2,119,277행. 단계 1의 Zeek 결과와 같다.
- manifest 5개 모두 검사를 통과했다. 크기는 Silver 106MB, 격리 84KB(빈 파일)다.
- 상위 폴더를 읽어 `capture_id` 열이 폴더 이름에서 만들어지는 것을 확인했다.

## 세 번째 작업: 캡처 시각 범위 manifest

Gold의 `capture_edge`와 월요일 80% 분할에는 캡처의 패킷 시각 최솟값·최댓값이 필요하다. 지금까지는 설계 문서에 월요일 값만 글로 적혀 있었다.
- [configs/captures.cic-ids-2017.v1.json](../configs/captures.cic-ids-2017.v1.json): `capture_id`, 원본 PCAP, Zeek 실행 폴더의 대응표.
- [scripts/capture_bounds.py](../scripts/capture_bounds.py): `capinfos -a -e -S -T -r`로 재서 `manifests/cic-ids-2017.capture-bounds.v1.json`에 쓴다.
  - 자릿수를 잃지 않도록 시각을 문자열로 둔다.
  - PCAP 해시는 입력 manifest 값을 쓴다.
- Claude 확인: 샘플 PCAP에서 `1499082958.598308`(11:55:58.598308 UTC)이 나왔다. 설계의 월요일 최소 시각과 같다.

캡처 시각 범위(사용자 실행, 2026-11-05, capinfos 4.2.2, UTC):

| capture_id | 최소 | 최대 | 길이 |
| --- | --- | --- | --- |
| cic17-mon | 07-03 11:55:58.598308 | 07-03 20:01:34.472889 | 8.09시간 |
| cic17-tue | 07-04 11:53:32.364079 | 07-04 20:00:31.076755 | 8.12시간 |
| cic17-wed | 07-05 11:42:42.084372 | 07-05 20:10:19.780725 | 8.46시간 |
| cic17-thu | 07-06 11:58:58.492265 | 07-06 20:04:44.364012 | 8.10시간 |
| cic17-fri | 07-07 11:59:39.599128 | 07-07 20:02:41.169108 | 8.05시간 |

월요일 값은 설계 6.1절과 같다.

## 네 번째 작업: 역할 관측과 창 라벨

- 설정: [captures 설정](../configs/captures.cic-ids-2017.v1.json)에 용도(`usage`)를 추가했다.
  - 월 `train_holdout`, 화 `development`, 수~금 `retrospective_eval`. 근거는 설계 6.1절이다.
- [zeek_ad/windows.py](../zeek_ad/windows.py): 두 함수를 추가했다. 테스트 2개를 더해 모두 22개가 통과했다.
  - `is_capture_edge`: 기존 `assign_split`의 경계 판정을 꺼낸 것이다.
  - `label_window`: 학습 캡처만 cutoff로 나눈다. 다른 캡처의 완전한 창은 용도 이름을 쓴다.
- [zeek_ad/role_windows.py](../zeek_ad/role_windows.py):
  - **판정 규칙의 위치:** `assets.py`·`windows.py` 한 곳에만 둔다. Spark에서는 그 규칙으로 작은 표를 만들어 조인한다. 작은 표는 점수화 대상 주소 14개와 창 라벨이다.
  - **자산 관점 변환:** responder 행은 바이트·패킷·포트 방향을 자산 관점으로 뒤집는다.
  - **창 시작:** `floor(write_ts/300)*300`.
- [scripts/inspect_role_windows.py](../scripts/inspect_role_windows.py): 읽기 전용이다. manifest가 있는 캡처만 읽는다. 폴더 기준 필터라 Spark는 해당 폴더만 읽는다(partition pruning).
- 실행 계획에서 주소 표 조인이 `BroadcastHashJoin`인 것을 확인했다. 큰 표를 shuffle하지 않는다.

Claude 확인(2026-11-05, 27초):

| 항목 | 값 |
| --- | --- |
| 점수화 대상 자산 | 14 |
| 역할 행 | 3,215,681 (Silver 2,119,277) |
| 양쪽 다 내부 자산인 연결 | 1,099,240 |
| 한쪽만 내부 자산인 연결 | 1,017,201 |
| 점수화 대상이 없는 연결 | 2,836. 지우지 않고 Silver에 남아 있다 |

월요일 창 수:

| 역할 | train | holdout | split_boundary | capture_edge |
| --- | --- | --- | --- | --- |
| originator | 958 | 235 | 12 | 22 |
| responder | 328 | 77 | 4 | 9 |

- 설계 6.1절의 사전 점검 수치와 **정확히 같다**: 출발 958·235, 수신 328·77, 수신 경계 4·양끝 9.
- 새 Zeek 실행(seed 고정)과 Spark 파이프라인으로 바꿨지만 창 수는 달라지지 않았다.

사용자 실행(2026-11-05): 위 Claude 확인과 같은 수치를 얻었다.

## 다섯 번째 작업: 특징 사전 초안

- [docs/feature-dictionary-v1.md](feature-dictionary-v1.md): 설계 3.3절을 18개 특징의 정확한 정의로 옮겼다. 결측, 분모, 분위수 방식을 포함한다.
- 사전을 정하기 전에 Silver 5일에서 측정한 사실(Claude, 2026-11-05):
  - `proto`: tcp 1,074,698, udp 1,043,723, icmp 759, unknown_transport 97.
  - `duration`·`orig_bytes`·`resp_bytes`는 항상 함께 결측이다. 결측 행은 37,121이다.
  - `service`가 `dns`인 행은 1,004,230이다. 쉼표가 든 값은 2,117행이고, `dns`가 섞인 쉼표 값은 없다.
  - `conn_state`는 13종이고, SF가 1,568,692로 가장 많다.

## 일정 변경(2026-11-05)

[DD-005](design-decisions/DD-005-deadline-scope.md): 2026-11-19 마감.
- 미루는 것: DD-004 클러스터, 단계 6, 결과 영향이 작은 검증.
- 꼭 필요한 검증만 둔다. 그 검증은 Claude가 직접 실행하고 보고한다.

## 여섯 번째 작업: Gold 특징과 게시

- [zeek_ad/gold_features.py](../zeek_ad/gold_features.py): 특징 사전 v1의 18개 특징과 진단 열 `eof_candidate_count`.
- [scripts/build_gold.py](../scripts/build_gold.py): 완료된 Silver 5일로 Gold를 만든다.
  - `conn_features_v1.tmp/`에 쓰고 검증한 뒤 `manifest.json`을 넣는다. 마지막에 폴더 이름을 `conn_features_v1/`로 바꿔 게시한다.
  - 검증 세 가지: 창별 연결 수의 합이 역할 행 수와 같은가, 키가 유일한가, 비율이 0~1 안에 있는가.
- [scripts/check_gold_sample.py](../scripts/check_gold_sample.py): 손계산 대조. Silver 원래 행에서 pandas·numpy로 따로 계산해 비교한다.
  - 고르는 창: 역할별 최대 연결 창, duration 전부 결측 창, 무작위 6개.
- Claude 최소 확인: 문법 검사, 합성 3행으로 API 오류 없음.

### 실행 결과(Claude, 2026-11-05)

- **첫 실행은 `OutOfMemoryError`로 실패했다.**
  - 원인: 정확한 분위수(`percentile`)는 창마다 duration 값을 모두 메모리에 모은다. local 모드의 기본 driver 메모리 1GB로는 12개 작업이 동시에 돌 때 부족했다.
  - 조치: `spark.driver.memory=8g`. local 모드에서는 driver가 executor를 겸한다.
- **재실행(27초):**
  - 역할 행 3,215,681, Gold 창 8,277. 검사 3개 모두 통과했다.
  - 창 수 표는 `inspect_role_windows.py`와 칸마다 같다. 월요일은 958·235·12·22 / 328·77·4·9다.
  - 게시 위치는 `outputs/gold/conn_features_v1/`(888KB)다.
- **손계산 대조:** 9개 창의 18개 특징이 모두 일치했다(`mismatched=0`).
  - 역할별 최대 연결 창: originator 3,345연결, responder 4,999연결.
  - duration이 전부 결측인 창(null 경로).
  - 무작위 6개.

단계 2 완료. 미룬 것: DD-004 클러스터, 재실행 동일성(DD-005).
