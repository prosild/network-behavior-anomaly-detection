# 단계 6 진행 기록: 파일 단위 자동 파이프라인(DD-012)

정식 스트리밍(설계 7.3절)이 아니라, 새 PCAP 파일 도착으로 시작하는 파일 단위 처리다. 결정 배경은 [DD-012](design-decisions/DD-012-file-triggered-pipeline.md), 켜는 방법은 [live-pipeline.md](live-pipeline.md).

## 첫째 작업: 수신 → 저장 → Zeek(2026-11-17)

### 만든 것
- 처리 기록 표 [db/migrations/004_ingest.sql](../db/migrations/004_ingest.sql) `zeekad.ingest_file`: 파일 해시(기본 키), 이름, 크기, 패킷 수, 첫·마지막 패킷 시각, 캡처 ID, Zeek 실행 폴더, status(received·zeek_done·pipeline_done·failed), error. worker 계정은 쓰기, API 계정은 읽기.
- 설정 [configs/pipeline/live.v1.json](../configs/pipeline/live.v1.json): `enabled: false`(기본 꺼짐), 수신·저장 폴더, 파일 패턴, 최소 대기 10초, 확인 주기 30초, 캡처 ID 접두사 `lab`, Zeek 설정 run.v2.
- 수신 처리 [zeek_ad/ingest.py](../zeek_ad/ingest.py), 감시 프로그램 [scripts/live_watcher.py](../scripts/live_watcher.py)(`--once`, 시험용 `--force`), tcpdump 회전 후 이동 도우미 [scripts/move_rotated.sh](../scripts/move_rotated.sh).
- 시험용 PCAP 생성기 [tests/pcap_fixture.py](../tests/pcap_fixture.py): 이 PC의 일반 계정은 캡처 권한(CAP_NET_RAW)이 없어서 실습망을 흉내 낸 패킷(10.10.0.0/24, DNS·HTTP)을 표준 라이브러리로 만든다. 운영 입력이 아니다.
- 시험 [tests/test_ingest.py](../tests/test_ingest.py) 2개 통과(파일 고르기·정렬, 캡처 ID 날짜).
- 생성 데이터 폴더 `/data/`는 gitignore에 넣었다(실습망 트래픽은 로컬에만).

### 실행 결과(시험 PCAP 2개, 2026-12-01 01:00·01:05 UTC 시작, 각 240패킷)
- 꺼진 상태: "꺼져 있다(enabled=false)"를 출력하고 끝남.
- 넣은 직후(`--force --once`): 처리 0개. 수정 후 10초가 안 된 파일은 쓰는 중일 수 있어 건너뛴다.
- 1분 지난 뒤: 2개 처리. 둘 다 `lab-20261201`, `zeek_done`. 파일은 `data/live/store/lab-20261201/`로 옮겨졌고 Zeek 출력은 `outputs/live/zeek/lab-20261201/lab-0100-11d40b72/` 등(conn 48행: HTTP 24·DNS 24, 모두 SF).
- 같은 내용을 다른 이름으로 다시 넣음: "이미 받은 파일(같은 해시)"로 `data/live/store/_duplicates/`에 치움. 처리 기록은 2행 그대로.
- 시험 데이터(처리 기록 2행, store·outputs/live 파일)는 다음 작업(Silver 이후 연결)의 시험 입력으로 남겨 둔다.

### 다음 작업
- 캡처 ID(그날)의 `zeek_done` 파일들을 모아 그날 전체를 다시 계산: Silver → Gold v1·v2 → 이벤트·그래프 → 채점 worker → 근거 → status `pipeline_done`.
- 기존 스크립트는 CIC 캡처 설정(`configs/captures.*`, 캡처 경계 manifest, 자산 설정)을 읽는다. 실습망 캡처용 설정을 어떻게 만들지(자동 생성) 먼저 정한다.

## 둘째 작업: 그날 다시 계산 1단위 — Zeek 합치기, 캡처 설정 자동 생성, Silver(2026-11-17)

### 방식
- 기존 배치 스크립트는 합성 캡처(DD-008) 때처럼 `--captures`·`--bounds`·`--out`만 바꾸면 새 캡처를 처리한다. 그래서 실습망 캡처에 필요한 세 가지를 자동으로 만들어 넘긴다: 합친 Zeek 폴더, 캡처 설정, 캡처 경계.
- **리비전**: 그날 지금까지 받은 파일 묶음. 이름은 `rev-<파일 수>-<파일 해시 묶음의 해시 8자리>`. 파일이 늘면 새 리비전 폴더에 처음부터 쓰고 이전 리비전은 그대로 둔다(기존 스크립트가 "완성된 결과는 덮어쓰지 않는다"는 규칙이라 그에 맞춤). 같은 묶음을 다시 부르면 아무것도 하지 않는다.
- 캡처 용도는 `live`다. 학습 캡처가 아니라 창을 나누지 않는다. 아직 다 받지 않은 마지막 창은 기존 규칙대로 `capture_edge`가 되어 채점 큐에서 빠진다. 다음 파일이 오면 그 창이 완성돼 채점된다.

### 만든 것
- [zeek_ad/live_capture.py](../zeek_ad/live_capture.py): `day_files`(ingest_file에서 그날 Zeek 완료 파일, 첫 패킷 순), `revision_id`, `merge_zeek`(같은 이름 로그를 파일 순서로 이어 붙이고 Silver가 읽는 run-manifest.json을 씀. Zeek 설정·이미지가 다른 파일이 섞이면 멈춤. packet_filter.log는 합치지 않음), `capture_config`(captures.json·capture-bounds.json).
- [scripts/live_recompute.py](../scripts/live_recompute.py) `--capture lab-YYYYMMDD`: 합치기 → 설정 → Silver. 단계별 소요 시간과 결과를 `pipeline.json`에 남긴다. 기존 스크립트는 고치지 않고 하위 프로세스로 부른다.
- [configs/assets.lab.v1.json](../configs/assets.lab.v1.json): 실습망 내부 대역. 지금은 시험 PCAP 대역 `10.10.0.0/24`이고, Kali 시험 전에 바꾼다. `live.v1.json`에 `runs_out`(outputs/live/runs)·`assets`를 더했다.
- [tests/test_live_capture.py](../tests/test_live_capture.py) 4개(리비전 이름, 합치기 순서·행 수·덮어쓰기 거부, 설정이 다른 파일 거부, 만든 설정을 배치 코드 `load_captures`가 읽음·`live` 창 라벨). 수신 시험과 함께 6개 통과.

### 실행 결과(시험 PCAP 2개, `lab-20261201`)
- 리비전 `rev-0002-f083cbda`. 합치기 conn 96행(48+48), 로그 4종. Silver 96행, 격리 0, 행 수 검사 통과. Silver 20초(대부분 Spark 시작).
- 다시 실행하면 "이미 끝난 리비전"으로 끝난다.
- 캡처 경계는 01:00:00\~01:06:50 UTC다. 5분 창 기준으로 완성된 창은 01:00\~01:05 하나뿐이고, 01:05 창은 `capture_edge`가 된다.

### 알려진 한계
- `eof_candidate`(Zeek가 끝날 때 한꺼번에 쓴 연결 표시)는 합친 로그 전체의 마지막 시각 기준이라 마지막 파일 끝만 표시된다(4행). 앞 파일 끝의 강제 기록 행은 표시되지 않는다. 파일 경계에서 연결이 잘리는 것과 같은 원인이다(DD-012 "정식 스트리밍과의 차이").

### 다음 단위
- Gold v1 → 이벤트 → Gold v2 → 그래프(월요일 원래 이벤트 + 그날). 자산 설정을 고정 경로(`assets.PROJECT_CONFIG`)에서 읽는 스크립트(build_gold, build_gold_v2, build_tgn_dataset, build_evidence)에 `--assets` 옵션을 더해야 한다(기본값은 지금 동작 그대로). 그래프는 월요일(CIC 대역)과 실습망 대역을 함께 써야 해서 두 대역을 합친 설정이 필요하다.

## 셋째 작업: 그날 다시 계산 2단위 — Gold v1 → 이벤트 → Gold v2 → TGN 그래프(2026-11-17)

### 바꾼 것
- 자산 설정 옵션 `--assets`(여러 개면 대역을 합침, 기본값은 CIC 설정 하나라 기존 동작 그대로): [build_gold.py](../scripts/build_gold.py), [build_gold_v2.py](../scripts/build_gold_v2.py), [build_tgn_dataset.py](../scripts/build_tgn_dataset.py). manifest에 쓴 자산 설정을 남긴다. 합치는 함수는 `assets.load_networks`. 시험 [tests/test_assets.py](../tests/test_assets.py)에 1개 추가.
- [build_tgn_events.py](../scripts/build_tgn_events.py) `read_log`: 그날 한 번도 없는 프로토콜은 Zeek가 로그 파일을 만들지 않는다(시험 캡처는 ssl.log 없음). 파일이 없거나 비면 행 없는 표를 돌려준다. CIC 캡처는 모든 로그가 있어 결과가 같다.
- [build_tgn_dataset.py](../scripts/build_tgn_dataset.py)
  - 이어 붙이기 전에 뒤 이벤트 표의 열 타입을 첫 표(월요일)에 맞춘다. 작은 하루 표는 값이 없는 열이 object로 읽혀 월요일 열 타입까지 바꿨다.
  - `categorical_columns`가 열 타입을 object로 고정한다. 이유는 아래 "환경 차이".
- [live_recompute.py](../scripts/live_recompute.py): Silver 뒤에 `gold_v1`, `events`, `gold_v2`, `graph` 단계를 이었다. 그래프는 월요일 원래 이벤트(`outputs/events/tgn_v1`) + 그날 이벤트이고, 자산 설정은 CIC + 실습망 두 개를 준다. 그래프 인코딩이 원래 월요일 그래프와 다르면 멈춘다.

### 실행 결과(`lab-20261201`, `rev-0002-f083cbda`)
- Gold v1 8창(`live` 4, `capture_edge` 4: 자산 4개 × 01:00 창·01:05 창), 19초. 이벤트 96행(Silver uid 누락 0), 17초. Gold v2 8창, 검사 통과, 20초. 그래프 14초.
- 그래프: 이벤트 375,528(월요일 375,432 + 실습망 96), 노드 9,743, 점수 대상 노드 18(CIC 14 + 실습망 4: 10.10.0.11·.12·.53·.80).
- 원래 그래프(`outputs/graphs/tgn_v1`)와 비교: 인코딩(어휘·표준화 값) 같음. 월요일 이벤트 375,432개의 uid 순서·범주·history·수치·DNS 가중치·시각이 모두 같음. 월요일 노드 9,739개의 노드 특징이 같음(실습망 대역을 더해도 월요일 노드 표시가 바뀌지 않음).

### 환경 차이(발견)
- `zeek-ad` 환경에서 실제로 불러오는 pandas가 3.1.0이다. 잠금 파일·requirements는 2.3.3이다.
- 2026-11-13 17:24에 conda로 seaborn·matplotlib을 설치할 때(EDA 작업) pandas 3.1.0이 pip 2.3.3 위에 덮어 설치됐다. site-packages에 두 버전의 dist-info가 함께 있어 `pip freeze`는 2.3.3으로 보고한다.
- 영향: pandas 3은 문자열·None 목록을 문자열 타입으로 바꾸며 None을 NaN으로 만든다. 그래서 그래프 어휘 정렬이 실패했다. 코드를 두 버전 모두에서 같은 결과가 나오게 고쳤다(위). 그래프 비교로 결과가 원래와 같음을 확인했다.
- 환경 자체는 고치지 않았다. 배포(DD-013) 이미지는 잠금 파일로 설치하므로 2.3.3이 된다. 로컬 환경을 잠금 파일대로 다시 만들지는 사용자가 정한다.
- 이 PC의 메모리는 다른 프로젝트 실험(약 52GB)이 쓰고 있어 큰 배열 비교 스크립트가 한 번 메모리 부족으로 끝났다(배열을 하나씩 읽게 바꿔 다시 확인).

### 다음 단위
- 채점 worker(Registry 묶음)와 근거 요약: 리비전마다 worker 입력 묶음 정의를 만들어 `run_worker.py`·`build_evidence.py`에 넘긴다. 결과는 DB의 새 채점 작업이 되고 대시보드 뷰에 나온다. 처리 기록 status를 `pipeline_done`으로 바꾼다.

## 넷째 작업: 그날 다시 계산 3단위 — 채점 worker·근거 요약·처리 완료 표시(2026-11-17)

### 바꾼 것
- [run_worker.py](../scripts/run_worker.py), [build_evidence.py](../scripts/build_evidence.py)에 `--inputs`(입력 묶음 정의 파일, 기본값은 `configs/worker/inputs.v1.json`), build_evidence에 `--assets`를 더했다.
- [live_capture.py](../zeek_ad/live_capture.py): 캡처 경계에 `pcap_sha256`(파일 해시 묶음의 해시)을 넣는다. 채점 결과에 남는 입력 캡처 해시 자리다. 이미 만든 리비전의 설정 파일은 다시 쓰지 않는다(Gold manifest가 그 해시를 기록하므로).
- [live_recompute.py](../scripts/live_recompute.py): 그래프 뒤에 `score`(리비전의 `worker-inputs.json`을 만들어 worker 실행) → `evidence` → `mark_done`(이 리비전 파일들을 `pipeline_done`으로).
- [evidence.py](../zeek_ad/evidence.py) `asset_observations`: kerberos.log·ntlm.log가 없으면 관측 없음으로 본다(실습망에는 없을 수 있다).
- 실패 파일 재처리: [ingest.py](../zeek_ad/ingest.py)의 Zeek 단계를 `run_zeek`로 떼고 `retry_failed`를 더했다. `python scripts/live_watcher.py --retry-failed`가 Zeek 단계에서 실패한 파일(저장 폴더에 있고 해시가 같은 파일)만 다시 처리한다. Zeek 오류 마지막 줄을 처리 기록 error에 남긴다.
- 시험 PCAP 생성기 [tests/pcap_fixture.py](../tests/pcap_fixture.py)에 `--scan ATTACKER TARGET PORTS`(닫힌 포트 SYN → RST, Zeek REJ. Kali nmap -sS 흉내)를 더했다.

### 실행 결과
- 기존 리비전(`rev-0002-f083cbda`)을 처음부터 다시 계산했다. 채점 작업 17(succeeded), 창 8개(점수 대상 live 4), **사건 0건**. 세 모델 점수가 모두 임계값 아래다(꼬리 3.33 < 5.55, TGN 최대 4.79 < 9.90, Transformer 최대 0.94 < 1.26). 평범한 DNS·HTTP만 있는 시험 트래픽이라 맞는 결과다. 근거 0행, 파일 2개 `pipeline_done`.
- 사건이 나오는 경로를 시험하려고 스캔이 섞인 PCAP 3개(01:10·01:15(10.10.0.66 → .80, 포트 1,000개)·01:20, 각 5분)를 넣었다. **세 파일 모두 Zeek 단계에서 실패했다.** Zeek는 docker로 실행하는데, 이 WSL 배포판에서 Docker Desktop 연동이 끊겨 `docker` 명령이 없다(`/usr/bin/docker`가 가리키는 `/mnt/wsl/docker-desktop/...`가 없음). DB 컨테이너는 Windows 쪽 Docker Desktop에서 계속 돌고 있어 접속된다.
- `--retry-failed`는 세 파일을 찾아 다시 시도했고, 같은 이유로 실패를 기록했다. Docker 연동을 되살리면 이 명령으로 이어서 처리한다.
- 사용자가 Docker Desktop의 WSL integration(Ubuntu)을 다시 켰다(11-12 WSL 시작 뒤로 끊겨 있었음). `docker version` Client·Server 29.8.2 확인, Postgres 컨테이너 healthy.

### 스캔 시험 결과(파일 5개, 리비전 `rev-0005-…`, 채점 작업 19)
- `--retry-failed`: 세 파일 Zeek 완료(패킷 600·2,600·600). 다시 계산 1분 42초: conn 1,456행 → Gold 21창(live 17, capture_edge 4) → 그래프(월요일 인코딩과 같음) → 채점 → **사건 4건**, 근거 4행 → 파일 5개 모두 `pipeline_done`.
- 큐(모두 01:15\~01:20 창, 스캔이 있던 창):

  | 순위 | 자산 | 역할 | 꼽은 모델 | 겹쳐 꼽은 모델 | 연결 |
  | --- | --- | --- | --- | --- | ---: |
  | 1 | 10.10.0.12 | originator | tgn_recon | — | 60 |
  | 2 | 10.10.0.66(스캐너) | originator | tail_rarity_v2 | transformer_v2 | 1,000 |
  | 3 | 10.10.0.80(스캔 대상) | responder | tgn_recon | tail_rarity_v2, transformer_v2 | 1,060 |
  | 4 | 10.10.0.11 | originator | tgn_recon | — | 60 |

- 해석:
  - 스캐너와 스캔 대상은 잡혔다. 대상 `.80`은 세 모델이 모두 꼽았다. 스캐너는 꼬리 희귀도(7.16 > 5.55)·Transformer(16.34 > 1.26)가 꼽았고, TGN은 8.03으로 임계값 9.90 아래였다.
  - 스캔이 없던 01:10 창과 01:00·01:05 창에서는 사건이 없다.
  - 평범한 클라이언트 `.11`·`.12`(DNS·HTTP만 60건, 모두 SF)가 같은 창에서 TGN으로만 꼽혔다(10.42·11.73). 이 둘은 스캔 대상 `.80`과 통신한다. TGN은 노드 기억(memory)을 이웃과 함께 갱신하므로, `.80`의 기억이 스캔으로 크게 바뀐 뒤 그와 통신한 연결의 재구성 오차가 커진 것으로 보인다. 그래프 모델의 이웃 전파 성질이다.
  - 결합 큐는 모델별 순위를 번갈아 놓으므로(DD-009) TGN 1위가 큐 1위가 됐다. 오탐이 큐 맨 위에 올 수 있다는 한계로 포트폴리오 문서에 적는다.

## 다섯째 작업: 감시 프로그램 → 다시 계산 자동 연결, uid 겹침 수정, 실습망 사건의 LLM 입력 확인(2026-11-17)

### 감시 프로그램 → 다시 계산
- [live_watcher.py](../scripts/live_watcher.py): 한 번 돌 때 1. 새 파일 → Zeek, 2. `zeek_done` 파일이 남은 날마다 `live_recompute.py --skip-failed`. 감시 프로그램이 멈췄다 켜져도 처리 기록에서 이어진다. 전에 실패한 리비전은 주기마다 반복하지 않는다(종료 코드 2, 직접 실행하면 다시 한다).
- 확인: 새 파일 없음 → "받은 파일 0개, 다시 계산한 날 0개". 새 파일 1개(01:25) → Zeek → 다시 계산(리비전 6개 파일) → 채점·근거까지 **2분 4초**. 대부분은 단계마다 Spark를 새로 띄우는 시간(단계당 15\~20초)이다.

### uid 겹침(발견·수정)
- Zeek seed를 고정했으므로(단계 1, 재현성) 파일마다 Zeek를 따로 돌리면 모든 파일이 같은 uid 순서로 시작한다(`CX2pCj3Xxbq0HT0MK6` …). 합친 conn 1,576행 중 uid 120개가 겹쳤고, DNS·HTTP 로그가 uid로 엉뚱한 연결에 붙었다. 스캐너 `.66`에 DNS 183건·HTTP 193건이 붙은 것으로 드러났다. Gold v2 로그 특징·TGN 입력·근거가 모두 오염됐다. CIC는 하루가 PCAP 하나라 영향 없다.
- 수정: [live_capture.py](../zeek_ad/live_capture.py) `merge_zeek`가 식별자 필드(uid, fuid, id, *_fuids 등)에 `-<파일 해시 6자리>`를 붙인다. 파일별 Zeek 출력은 그대로다. 시험 추가(같은 uid가 두 파일에 있어도 합친 뒤 다르고, 다른 필드는 그대로), 5개 통과.
- 오염된 실습망 결과를 지웠다: 채점 작업 17·19·20(`lab-20261201`, cascade로 창 점수·사건·근거), 리비전 폴더. CIC·합성 작업 8개는 그대로.
- 다시 계산(작업 21): 사건 4건(모두 01:15 창 시작)

  | 순위 | 자산 | 역할 | 꼽은 모델 | 겹쳐 꼽은 모델 | 연결 |
  | --- | --- | --- | --- | --- | ---: |
  | 1 | 10.10.0.80(스캔 대상) | responder | tgn_recon | tail_rarity_v2, transformer_v2 | 1,120 |
  | 2 | 10.10.0.66(스캐너) | originator | transformer_v2 | tail_rarity_v2 | 1,000 |
  | 3 | 10.10.0.12 | originator | tgn_recon | — | 120 |
  | 4 | 10.10.0.11 | originator | tgn_recon | — | 120 |

  스캐너의 DNS·HTTP 사실은 0으로 바로잡혔다. 넷째 작업의 표(작업 19)는 uid 겹침 전 결과라 이 표로 대신한다. TGN만 꼽은 `.11`·`.12`는 01:15·01:20 두 창이 후보(이웃 전파 해석은 같다).

### 실습망 사건의 LLM 입력(사례 하나: 스캐너 `.66`, 작업 21)
- [agent_inputs.py](../zeek_ad/agent_inputs.py) `InputContext(assets=…, worker_inputs=…)`: 내부 대역과 Gold 위치를 실습망 리비전 것으로 받는다. 기본값은 CIC 그대로.
- 입력: 사실 52개, 가명 `H`=10.10.0.66, `I1`=10.10.0.80(내부로 바르게 판정). 월요일 기준 창이 없어 `baseline_windows 0`, 기준 통계는 모두 null.
- LLM 응답(gemini-3.7-flash 요청 → 3.8-flash, 21초, 토큰 3,111·1,400·thinking 1,113): 검증 통과. 요약·주장은 사실과 맞고 전송 의견 send("비정상 네트워크 스캔 정황"). 기준 창 0개를 한계로 적었다.
- **문제: ATT&CK 해석이 빗나갔다.** 검색 후보 5개(T1090.001 Internal Proxy, T1205.001 Port Knocking, T1499.001 OS Exhaustion Flood, T1049, T1571)에 T1046(Network Service Discovery)이 없어, LLM이 후보 안에서 포트 노킹·자원 고갈 같은 해석을 골랐다. 같은 검색 문장에서 T1046은 8위다. CIC 포트 스캔 사건(eval-13)에서도 빠졌고 보고서 60건 중 2건에만 있었다. 실습망 문제가 아니라 검색(5a)의 약점이다. 처리 방법은 사용자와 정한다.

## 여섯째 작업: 검색 후보 10개, 템플릿 알림 먼저, 실습망 사건 → LangGraph 자동 연결(2026-11-17, Q52·Q53)

### 검색 후보 5 → 10(`configs/rag/retrieval.v2.json`)
- 근거: 5a 평가(질의 16개)의 Gemini 첫 정답 순위로 계산하면 hit@5 15/16, hit@10 16/16.
- [agent_inputs.py](../zeek_ad/agent_inputs.py)의 `RETRIEVAL`을 v2로 바꿨다. 동결 파일(`retrieval.v1.json`, `rag.py`)의 해시는 그대로다(rag.py 설명 문장을 고쳤다가 동결 해시 때문에 되돌렸다). 동결 평가를 다시 만들려면 v1을 쓴다.
- 같은 스캐너 사건으로 다시 확인(DB에 쓰지 않음): 후보 10개에 T1046(8위)이 들어왔고, LLM 해석 첫째가 T1046 "네트워크 서비스 탐색"이 됐다. 검증 통과.

### 템플릿 알림 먼저(Q47 구현)
- [agent_graph.py](../zeek_ad/agent_graph.py)에 `early_alert` 노드(rag 뒤, write_report 앞). 정책 규칙만으로 보냄이면 템플릿 보고서로 Slack 알림을 기록한다. deliver는 LLM 보고서가 나오면 "LLM 보고서 추가" 줄을 붙여 한 번 더 기록한다(보고서 버전이 달라 다른 메시지). LLM이 실패해 템플릿이면 같은 키라 다시 남지 않는다.
- [slack.py](../zeek_ad/slack.py) `incident_message`: 판단 모델 의견이 아직 없으면 "LLM 보고서와 판단 모델 의견은 뒤따른다"로 쓴다. `note` 줄 추가.
- 시험: 그래프 시험 8개(템플릿 먼저 → LLM 순서, 정책 보류면 알림 없음 추가). 관련 시험 모두 통과.

### 실습망 사건 → LangGraph
- [scripts/live_agent.py](../scripts/live_agent.py) `--capture`: 그날 최신 성공 작업의 사건 중, 같은 사건 ID를 그날 다른 작업에서 이미 처리하지 않은 것만 그래프에 넣는다(리비전이 바뀌어도 다시 알리지 않게). 입력 설정은 그 리비전의 `worker-inputs.json`과 `assets.lab.v1.json`. [run_agent_graph.py](../scripts/run_agent_graph.py) `resources(ctx_options)`를 재사용한다.
- [live_watcher.py](../scripts/live_watcher.py): 다시 계산이 성공하고 설정 `agent`가 true면 `live_agent.py`를 부른다(`live.v1.json`에 `"agent": true`).

### 실행 결과(작업 21, 사건 4건, 2분 55초)
| 자산 | 그래프 시간 | 템플릿 알림까지 | LLM | 판단(정책·LLM·판단 모델) | 해석(ATT&CK) |
| --- | ---: | ---: | --- | --- | --- |
| .80 스캔 대상 | 40.2초 | 1.8초 | 검증 통과, 35.7초 | send·send·send(0.47) | T1049, T1071.001, T1571 |
| .66 스캐너 | 38.6초 | 1.6초 | 검증 통과, 35.2초 | send·send·send(0.49) | T1046, T1498·T1499.002 |
| .12 평범한 클라이언트 | 43.6초 | 1.5초 | 검증 통과, 40.0초 | send·**hold·hold**(0.47) | T1071.004, T1016.001 |
| .11 평범한 클라이언트 | 48.0초 | 1.6초 | 검증 통과, 44.7초 | send·**hold·hold**(0.51) | T1071.004, T1572 |

- Slack dry-run 8건(사건마다 템플릿 1 + LLM 1). 분석가 대기 0건. MLflow trace 4개(실험 zeekad-agent-traces).
- 관찰:
  - TGN만 꼽은 평범한 클라이언트 둘은 LLM과 판단 모델이 모두 hold였다. 정책 규칙(큐 5위 이내 필수 전송)이 보냄으로 정했다. A단계(정책 규칙이 결정) 한계가 실습망에서도 그대로 보인다.
  - 스캔 대상(.80, responder)의 후보 10개에는 T1046이 없었다(받는 쪽 검색 문장은 "많은 포트로 연결을 받음"이라 스캔 기법과 거리가 멀다). 스캐너 쪽은 T1046을 골랐다.
  - LLM thinking 토큰이 2,500\~4,000이고 보고서마다 35\~45초다(앞 한 건 시험은 11초, thinking 없음). 호출마다 편차가 크다.
  - 템플릿 알림은 사건마다 그래프 시작 1.5\~1.8초 뒤에 기록됐다. 하지만 사건을 차례로 처리하므로 4번째 사건의 템플릿 알림은 첫 사건보다 2분 늦었다. 모든 사건의 템플릿 알림을 먼저 보내고 LLM 보고서를 그 뒤에 돌리면 줄일 수 있다(다음 개선 후보).

## 일곱째 작업: 템플릿 알림을 모든 사건에 먼저(2026-11-17)

- 문제: 사건을 하나씩 끝까지 처리해서, 사건이 4건이면 4번째 사건의 첫 알림이 첫 사건보다 2분 늦었다(여섯째 작업).
- [live_agent.py](../scripts/live_agent.py)를 두 차례로 나눴다. 1차: 모든 사건을 `early_alert` 뒤에서 멈춘다(LangGraph `interrupt_after`, 상태는 checkpoint). 2차: 같은 thread_id로 이어서 LLM 보고서·판단·전송 기록. 중간에 멈춰도 다음 실행이 1차부터 다시 하고, Slack 기록은 중복 방지 키라 한 번만 남는다.
- 시험: [tests/test_agent_graph.py](../tests/test_agent_graph.py)에 두 사건 두 차례 처리 시험 추가(기록 순서 template, template, llm, llm). 9개 통과.
- 감시 프로그램 전 과정 시험(사람 손 없이 `live_watcher.py --force --once` 두 번):
  - 01:30 파일(10.10.0.77 → DNS 서버 .53, 포트 500개 스캔): Zeek → 다시 계산(133초) → 새 사건 0건. 스캔 창(01:30)이 그날 마지막 창이라 아직 다 받지 않은 창(`capture_edge`)이다. 설계대로다.
  - 01:35 파일(평범한 트래픽): 01:30 창이 완성돼 채점됐다. 다시 계산 113초 → 작업 23(사건 6건) → 이미 처리한 사건 4건은 건너뛰고 새 사건 2건만 그래프로.
  - 템플릿 알림: `.77` 09:50:15, `.53` 09:50:18(3초 차이). LLM 보고서 알림: 09:50:49, 09:51:12. 둘 다 검증 통과, 세 판단 모두 send. 스캐너 `.77` 해석 첫째 T1046.
  - 지연(파일 수신부터): 템플릿 알림 약 2분(대부분 다시 계산), LLM 보고서 알림 약 2.5분. 다시 계산은 단계마다 Spark를 새로 띄우는 시간이 크다. NAS(J4125, 4코어)에서는 더 느릴 것이라 배포 때 단계별 시간을 다시 잰다.
- 처리 기록: 파일 8개 모두 `pipeline_done`.

## 여덟째 작업: 배포 방향 VMware로 변경(DD-015), 데이터 계약 v2.1(2026-11-17, Q54)

- 사용자 결정: NAS 대신 이 PC의 VMware에 배포 VM 하나 + Kali VM(격리 host-only 실습망). [DD-015](design-decisions/DD-015-vmware-lab-deployment.md)가 DD-013을 대체한다. 근거: 추론은 CPU로 충분(CIC 하루 세 모델 15\~24초), NAS 실데이터 보호, 실습용 카드만 캡처해 자기 트래픽 필터가 필요 없음.
- 발견: 실습망은 같은 캡처에 작업이 여러 개(21·22·23) 생겨, `(job_id, incident_id)`로 조인하면 최신 작업에서 보고서가 없고 상태가 open으로 되돌아간 것처럼 보였다.
- [012_incident_identity.sql](../db/migrations/012_incident_identity.sql)
  - `incident_status` 키를 `incident_id`로(열 `job_id` → `last_job_id`), 작업 외래 키 제거(작업을 지워도 판단은 남음). `incident_status_history`도 작업 외래 키 제거(감사 기록).
  - `transition_incident`: 호출 모양 그대로, 사건 ID로 잠그고 바꾼다. `p_job`은 그 작업에 사건이 있는지 확인에만 쓴다.
  - `dashboard.incident_status`: 열 그대로, 사건 ID로 조인.
  - 새 뷰 `dashboard.latest_incident_queue`: 캡처별 최신 성공 작업의 큐 + 보고서가 있는 작업(`zeekad_report_job_id`)·보고서 종류·전송 여부·상태·검토.
- [agent_graph.py](../zeek_ad/agent_graph.py) `apply_status`가 상태를 사건 ID로 읽는다. 그래프 시험 9개 통과.
- 확인: 최신 큐는 캡처 9개(CIC 4·합성 4·실습 1). `lab-20261201` 작업 23의 6건 중 4건은 보고서 작업 21, 2건은 23. 작업 23에서 `.80`을 확인 중으로 바꾸자 작업 21·22·23 모두 확인 중. 작업 21에서 같은 변경은 거부(`22023`), 사건이 없는 작업 번호는 거부(`02000`). CIC의 기존 상태 2건은 그대로.
  - 시험으로 바꾼 `.80`(실습망 시험 데이터)의 상태는 확인 중으로 남아 있다(상태는 앞으로만 간다).
- 문서: [데이터 계약 v2](data-contract-v2.md)에 v2.1 절, [Java brief](java-dashboard-agent-brief.md) 1장(배포·실습망 캡처)·2장(v2.1 조인 규칙)·쓰기 예시.

## 아홉째 작업: 파이프라인 컨테이너 이미지와 결과 동일성 검증(2026-11-17, DD-015 배포 1단위)

### 만든 것
- [deploy/pipeline/Dockerfile](../deploy/pipeline/Dockerfile): 바탕은 Zeek 공식 이미지(`run.v2.json`의 digest, Debian 13·Python 3.13). Java 21(Spark), capinfos, tcpdump, 가상 환경에 Python 패키지. 코드·설정만 이미지에 넣고 데이터(outputs/, data/)는 볼륨, 비밀값은 환경 변수. 일반 계정(uid 1000)으로 돈다.
- [requirements.runtime.txt](../deploy/pipeline/requirements.runtime.txt): 운영에 쓰는 패키지만(EDA·노트북·bge 비교 제외). [constraints.runtime.txt](../deploy/pipeline/constraints.runtime.txt): 잠금 파일에서 만든 의존성 버전 고정(GPU 전용·conda 로컬 경로 제외). torch는 CPU 빌드(2.15.0+cpu).
- [.dockerignore](../.dockerignore): 코드·설정만 빌드에 보낸다(원본 PCAP·outputs·비밀값 제외).
- [run_zeek.py](../scripts/run_zeek.py): `ZEEKAD_ZEEK_RUNNER=local`이면 컨테이너 안의 zeek를 바로 부른다(설정과 Zeek 버전이 같은지 확인). 기본은 지금처럼 docker. 실행 기록에 runner를 남긴다. Docker 소켓을 컨테이너에 넘기지 않으려는 선택이다.
- [zeek_ad/db.py](../zeek_ad/db.py) `db_address`: DB 주소를 `POSTGRES_HOST`·`POSTGRES_PORT`로 받는다(기본 127.0.0.1:55432). LangGraph checkpoint 연결도 같다.

### 확인
- 이미지 4.8GB, 빌드 약 2분(받는 시간 제외). 안의 버전: Python 3.13.5, Java 21.0.13, Zeek 8.0.10, capinfos 4.4.19, torch 2.15.0+cpu, pandas 2.3.3(잠금 파일과 같음), pyspark 4.3.0. 이미지 안에서 시험 65개 통과.
- 결과 동일성: 컨테이너(Compose 네트워크로 DB 접속)에서 `lab-20261201` 파일 8개를 처음부터 다시 계산해(별도 폴더) 작업 24를 만들고, conda 환경의 작업 23과 비교했다. **창 점수 102개 모두 같음(최대 차이 0.0)**, 사건 6건(순위·꼽은 모델)과 근거 JSON 같음. 비교 뒤 작업 24와 시험 폴더를 지웠다.
- 단계 시간(컨테이너): 이벤트 27초, Gold v2 25초, 그래프 18초, 채점 11초.

### 배포 때 처리할 것(발견)
- MLflow 모델 artifact 위치가 절대 경로(`file:///home/prosild/src/zeek_AD/outputs/mlflow/artifacts/...`)로 DB에 기록돼 있다. 시험에서는 같은 경로로 한 번 더 붙여 해결했다. 배포 VM에서는 artifact 위치를 새 경로로 바꾸는 이전 작업이 필요하다. 모델을 불러올 때 MLflow가 그 폴더에 파일을 쓰므로 읽기 전용으로 붙이면 안 된다.


## 열째 작업: 배포 VM용 Compose 구성(2026-11-18, DD-015 배포 2단위)

### 만든 것
- [deploy/compose.yaml](../deploy/compose.yaml): 기존 `postgres`는 그대로 두고 `app` 프로필 서비스 4개를 더했다. 이 PC에서 프로필 없이 `up -d`를 하면 지금처럼 Postgres만 뜬다.
  - `pipeline`: 감시 프로그램(Zeek → 다시 계산 → 채점 → 근거 → 에이전트). 볼륨 `outputs/`, `data/live/`. `ZEEKAD_LIVE_ENABLED=1`로 켠다.
  - `collector`: [capture_lab.sh](../scripts/capture_lab.sh)로 실습망 카드(`LAB_IFACE`)만 캡처해 `ROTATE_SECONDS`마다 수신 폴더로 넘긴다. 호스트 네트워크를 쓰고 포트를 열지 않는다.
  - `api`: 근거 API. `127.0.0.1:8000`에만 연다(대시보드는 컨테이너 네트워크 안에서 `http://api:8000`).
  - `mlflow`: MLflow 화면. 관리용 주소 `MGMT_BIND`에만 열고, artifact 폴더는 읽기 전용으로 붙인다.
  - Java 대시보드 자리는 주석으로 남겼다(대시보드 이미지가 나오면 더한다).
- 노출과 권한
  - 실습망 카드에는 어떤 포트도 열지 않는다. Docker 포트 공개는 ufw보다 앞서므로 주소를 모두 적었다(DB·API 127.0.0.1, 화면은 `MGMT_BIND`).
  - 비밀값은 서비스마다 필요한 것만 넘긴다(API는 `ZEEKAD_API_PASSWORD` 하나, MLflow는 `MLFLOW_DB_PASSWORD` 하나 등). `.env` 전체를 넘기지 않는다.
  - `pipeline`·`api`·`mlflow`: 모든 capability 제거, `no-new-privileges`. `collector`: NET_RAW·SETUID·SETGID만.
- 코드
  - [db.py](../zeek_ad/db.py) `ENV_KEYS`: `.env` 파일이 없는 컨테이너에서도 환경 변수의 `GEMINI_API_KEY`를 읽는다. 이전에는 파일에 있는 키만 환경 변수로 덮을 수 있어, 컨테이너의 에이전트가 키를 못 찾았을 것이다(아홉째 작업은 다시 계산까지만 시험해서 드러나지 않았다).
  - [live_watcher.py](../scripts/live_watcher.py): 환경 변수 `ZEEKAD_LIVE_ENABLED=1`이면 설정의 `enabled`(이 PC 기본값 false)를 덮는다.
  - [run_api.py](../scripts/run_api.py) `--host`·`--port`, [mlflow_ui.py](../scripts/mlflow_ui.py)는 인자를 `mlflow server`에 그대로 넘긴다. 기본값은 이전과 같다.
- [.env.example](../deploy/.env.example): `GEMINI_API_KEY`, `MGMT_BIND`, `LAB_IFACE`, `ROTATE_SECONDS`, `API_PORT`, `MLFLOW_UI_PORT`.

### 확인(이 PC)
- `docker compose config`: 프로필 없이 `postgres`만, `--profile app`이면 5개.
- `api`·`mlflow`: 둘 다 healthy. API `/health`와 `lab-20261201` 큐(작업 23) 응답, MLflow 화면 200·실험 목록 조회. 확인 뒤 두 컨테이너는 내렸다(이 PC의 8000·5000 포트를 비워 둔다).
- `collector`(같은 권한으로 Compose 네트워크의 eth0에서, 5초 회전): 남아 있던 파일 1개를 수신 폴더로 옮기고, 회전 파일 3개(패킷 18·13·10)가 uid 1000 소유로 수신 폴더에 들어왔다. 쓰는 중인 파일은 spool에 남았다. 프로세스 권한은 NET_RAW 하나.
  - 처음 방식(`tcpdump -Z`)은 실패했다. Debian tcpdump는 첫 파일을 root로 열고 주인을 바꾸므로 root에게 DAC_OVERRIDE·CHOWN이 필요했다. 그래서 tcpdump를 처음부터 uid 1000으로 실행하고 NET_RAW만 ambient capability로 넘겼다.
- `pipeline`(capability 없음): 감시 프로그램 한 번 실행(받은 파일 0개, DB 접속 성공), Gemini 키 전달 확인(값은 출력하지 않음), Zeek 실행(파일 하나에서 conn 1,129행).
- 시험 114개 통과(conda 환경).
- 부수 발견: 이 PC의 `zeekad-postgres-1`이 이번 `up`에서 다시 만들어졌다. 원인은 이전 작업에서 Compose의 postgres 환경 변수에 `DASHBOARD_APP_PASSWORD`를 더하고 컨테이너를 다시 만들지 않은 것이다. 데이터 볼륨(`zeekad_pgdata`)은 그대로이고(작업 11개, 보고서 66건, 수신 파일 8개), 이후 `up`은 다시 만들지 않는다.

### 다음(데이터 이전 단위)
- MLflow artifact 위치를 VM 경로(`/app/outputs/mlflow/artifacts`)로 바꾼다. 실험 `zeekad-agent-traces`·`Default`의 위치는 프로젝트 루트의 `mlruns/`(없는 폴더, trace는 DB에 있다)로 돼 있어 함께 바꾼다.
- DB 덤프·복원, VM에 필요한 `outputs/` 부분만 복사(모델 artifact, 월요일 이벤트, 근거·RAG 입력 등. 목록을 정해야 한다).
- VM 생성 안내(Ubuntu Server, 카드 두 개, `LAB_IFACE`·`MGMT_BIND`, 실습망 대역을 `assets.lab.v1.json`에), [live-pipeline.md](live-pipeline.md) 갱신.

## 열한째 작업: 배포 묶음 내보내기·가져오기와 리허설(2026-11-18, DD-015 배포 3단위)

### 만든 것
- [deploy/export_bundle.sh](../deploy/export_bundle.sh)(이 PC): DB `zeekad`·`mlflow` 덤프(`pg_dump -Fc`, 컨테이너 안 superuser) + 실시간 처리에 필요한 파일만 tar + `manifest.json`(이 PC 프로젝트 경로 `old_root`) + `SHA256SUMS`.
  - 파일 목록: MLflow artifact, 월요일 이벤트(`events/tgn_v1`의 `cic17-mon`과 manifest), 월요일 그래프 `encoding.json`, Gold v2(LLM 입력 비교 기준), 실습망 시험 데이터(`outputs/live/zeek`, `data/live/store`). outputs 9.0GB 중 46MB.
  - 넣지 않는 것: `zeekad_dashboard` DB(대시보드가 Flyway로 VM에서 만든다), 비밀값(`deploy/.env`), 리비전 폴더(`outputs/live/runs`).
- [deploy/import_bundle.sh](../deploy/import_bundle.sh)(VM): 해시 확인 → Postgres만 띄움(다른 서비스가 돌면 멈춤) → 두 DB가 비었는지 확인(덮어쓰지 않음) → `pg_restore --single-transaction` → MLflow DB의 모든 문자열 열에서 `old_root`를 `/app`으로(`mlruns/`는 `/app/outputs/mlflow/mlruns/`로) 바꾸고 두 DB에 남은 곳이 0인지 확인 → 파일 풀기.
  - 이 PC 경로가 들어 있던 곳(조사): `experiments.artifact_location` 4, `runs.artifact_uri` 32, `logged_models.artifact_location` 1, `model_versions.storage_location` 1, `trace_tags.value` 9, `trace_request_metadata.value` 4. zeekad DB에는 없다.
  - 모델 파일(MLmodel)의 절대 경로는 기록일 뿐이라 고치지 않는다(불러올 때는 모델 폴더 안의 파일을 쓴다). 리허설에서 확인했다.

### 리허설(이 PC, 별도 Compose 프로젝트)
- `COMPOSE_PROJECT_NAME=zeekad-rehearsal`, 포트 55433·8001·5001, `ZEEKAD_ROOT`는 임시 폴더. 실제 DB 볼륨·outputs는 건드리지 않았다(시작 전 `docker compose config`로 이름·볼륨·마운트를 확인).
- 묶음 52MB(zeekad 덤프 5.5MB, mlflow 덤프 176KB, 파일 46MB). 가져오기: 표 zeekad 22개·mlflow 65개, 경로 51곳 변환, 남은 곳 0.
- 리허설 DB에서만 `lab-20261201` 파일 8개를 `zeek_done`으로 되돌리고 `pipeline` 서비스로 감시 프로그램을 한 번 실행했다.
  - 다시 계산 170초 → 작업 25. **작업 23과 창 점수 102개 모두 같음(최대 차이 0)**, 사건 6건(순위·꼽은 모델·점수)과 근거 같음. 줄인 파일 목록으로 충분하고, 바뀐 MLflow 경로로 모델을 불러온다는 뜻이다.
  - 에이전트: 6건 모두 이미 보고서가 있어 처리 0건(Gemini 호출 없음). `latest_incident_queue`는 작업 25를 가리키고 6건 모두 보고서 작업이 붙는다(v2.1).
  - API(작업 25 큐)와 MLflow 화면(모델 버전 READY, run artifact 목록 `file:///app/outputs/...`) 정상.
- 리허설 프로젝트와 볼륨, 임시 폴더는 지웠다. 실제 `zeekad-postgres-1`은 그대로다.

### 다음
- VM 생성 안내 문서(Ubuntu Server, 카드 두 개, Docker 설치, 코드·`.env`·묶음 옮기기, `LAB_IFACE`·`MGMT_BIND`, 실습망 대역을 `assets.lab.v1.json`에), [live-pipeline.md](live-pipeline.md) 갱신.

## 열두째 작업: 배포 VM 만들기 안내와 사양 실측(2026-11-18, DD-015 배포 4단위)

### 만든 것
- [vm-deployment.md](vm-deployment.md): VMnet2(host-only, Windows 연결·DHCP 없음, 10.10.0.0/24) → 배포 VM(카드 NAT·VMnet2, 실습망 카드는 고정 IP·기본 경로 없음) → Docker → 묶음·`.env` 옮기기 → 빌드·가져오기·띄우기 → 노출·격리 확인 → Kali(VMnet2 카드 하나, 10.10.0.50) → 첫 동작 확인.
- 실습망 대역은 시험 PCAP과 같은 `10.10.0.0/24`로 정했다. `assets.lab.v1.json`을 고치지 않는다(DD-015 "배포 전에 할 일" 갱신).
- [export_bundle.sh](../deploy/export_bundle.sh): 묶음에 코드(`code.tar`, 900KB, `deploy/.env`·`__pycache__` 제외)를 더했다. 이 프로젝트는 git 저장소가 아니라서 코드도 함께 옮긴다. Gemini 키 형식 문자열이 들어 있지 않은지 확인했다.

### VM 절차 모의(이 PC, Compose 프로젝트 `zeekad-vmsim`)
- 빈 폴더에 `code.tar`만 풀고 `.env`를 넣은 뒤 이미지를 빌드했다(빌드 성공. 같은 내용이라 캐시 사용) → `import_bundle.sh`(기본 `ZEEKAD_ROOT`, 즉 그 폴더) → 실습망 하루 다시 계산.
- CPU 4개 제한(`--cpus 4`), capability 없음: 다시 계산 167초(단계별 Silver 31·Gold v1 33·이벤트 32·Gold v2 31·그래프 17·채점 20초), 컨테이너 최고 메모리 1.97GB, 리비전 86MB. 작업 23과 창 점수 102개 같음(최대 차이 0).
- 사양 결정: 배포 VM CPU 4, 메모리 8GB, 디스크 60GB. 모의 환경(프로젝트·볼륨·이미지 태그·폴더)은 지웠다.

### 다음
- 사용자가 [vm-deployment.md](vm-deployment.md) 1\~11단계로 VM 두 대를 만든다. 묶음 만들기(8단계 이 PC 쪽)는 그때 Claude가 실행할 수 있다.
- 2026-11-18 사용자 요청으로 안내를 처음부터 따라 하는 수준으로 다시 썼다. 설치 중 질문(CPU 표기, 설치 프로그램의 `Network configuration` 화면, 카드 이름이 `ens33`·`eth`로 보이는 것, IPv6)을 반영했다.
  - 설치는 NAT 카드 하나로 하고, 실습망(VMnet2) 카드는 설치 뒤에 단다. 설치 프로그램이 실습망 카드를 DHCP로 설정해 부팅이 멈추는 일을 막는다.
  - NAT 카드는 IPv4 DHCP, IPv6 Disabled. 디스크는 LVM을 끈다(켜면 `/`가 디스크 절반만 받는다). Featured snaps에서 docker를 고르지 않는다.
  - SSH는 WSL 키 로그인(`~/.ssh/config`의 `zeekad-vm`)으로 하고 비밀번호 로그인을 끈다(`sshd_config.d/01-zeekad.conf`. `50-cloud-init.conf`보다 먼저 읽혀야 한다).
  - 스냅숏 두 곳(`docker-ready`, `pipeline-up`)과 끄고 켜는 방법을 더했다.
- 장시간 시험 전에 리비전 정리 기능을 만든다.

## 열셋째 작업: 배포 VM 실제 설치와 첫 수집(2026-11-18, DD-015 배포 5단위)

### 사용자가 한 것
- [vm-deployment.md](vm-deployment.md) 0\~11단계. 배포 VM `zeekad-deploy`(Ubuntu Server 24.04, NAT 카드 `ens32` 192.168.36.129, 실습망 카드 `ens34` 10.10.0.10), Kali(`eth0` 10.10.0.50, NetworkManager 연결 `lab`). 스냅숏 `pipeline-up`.
- 설치 중 나온 질문으로 안내를 고쳤다: VM이 꺼져 있으면 `Connected`가 회색, 목록에 `VMnet2`만 보임, netplan 파일은 `sudo`로 읽음, MLflow 3은 메뉴가 왼쪽(`/#/models`), Kali는 DHCP 실패로 처음에 `Disconnected`(정상), 기존 연결을 고치는 대신 우선순위 높은 `lab` 연결을 새로 만든다.

### Claude가 한 것
- 묶음을 새로 만들어(`~/zeekad-bundle`, 비밀값·키 형식 없음 확인) `ssh zeekad-vm`으로 묶음과 `.env`를 보냈다. VM에서 해시 5개 OK.
- 9·10단계 확인: 서비스 5개 정상, 표 zeekad 22·mlflow 65, 이 PC 경로 0, 포트(DB·API는 127.0.0.1, MLflow는 192.168.36.129, 실습망 주소에는 SSH만), WSL에서 MLflow `/health` OK, `zeekad-fusion` 버전 1 READY. 배포 VM → Kali ping 성공.

### 발견한 문제와 수정
- **실습망 파일의 Zeek 단계가 컨테이너에서 실패했다**: `FileNotFoundError: /app/manifests/cic-ids-2017.inputs.v1.json`.
  - 원인: `scripts/run_zeek.py`가 CIC 원본 해시를 재사용하려고 입력 manifest를 늘 읽는다. 이미지에는 `manifests/`가 없다(CIC 원본이 없으니 넣지 않았다).
  - 리허설에서 못 잡은 이유: 리허설과 VM 모의는 이미 `zeek_done`인 파일로 다시 계산만 했다. 새 파일의 Zeek 단계는 컨테이너에서 처음 돌았다.
  - 수정: manifest가 없으면 해시를 직접 계산한다(`sha256_source: computed`. 실습망 파일은 원래 manifest에 없어 결과가 같다). 시험 114개 통과.
  - VM에는 이 파일 하나를 보내 `pipeline` 이미지를 다시 빌드했다. 다음 묶음(`code.tar`)에는 고친 파일이 들어간다.
  - `--retry-failed`로 실패한 파일(패킷 60개)을 다시 처리해 `zeek_done`. 새 파일(패킷 26개)은 감시 프로그램이 Zeek → 다시 계산(100초) → 에이전트(사건 0건)까지 끝냈다(작업 25, `rev-0001`).
- 참고: 수집을 시작한 뒤 첫 파일은 트래픽이 없어 비어 있었다(`패킷이 없는 파일`로 실패 기록, 다음 확인 때 같은 해시로 `_duplicates`에 치움). tcpdump `-G`는 다음 패킷이 와야 파일을 바꾸므로 트래픽이 없으면 새 파일도 생기지 않는다.

### 12단계 첫 동작 확인(Claude가 VM에서 확인, 사용자 자리 비움)
- 사용자가 09:49(UTC) Kali에서 `ping -c 20`, `nmap -sT -p 1-100 10.10.0.10`을 실행했다. 패킷 248개 파일.
- 끝까지 이어졌다: 수집 → Zeek → 다시 계산(84\~120초) → 에이전트(LLM 보고서 4건, 검증 통과, 판단 모델 호출, Slack은 dry_run). 작업 25\~28, 리비전 rev-0001\~0004.
- 큐(작업 28): 1·2위 `10.10.0.50 originator`·`10.10.0.10 responder` 09:40\~09:50, 연결 103개(nmap 포함, tail_rarity_v2가 꼽음), 3·4위는 반대 방향 09:40\~09:45 연결 1개. 09:40 창은 Kali 격리 확인(ping, `curl :5000` REJ)이다.

### 발견한 문제 두 가지(결정 대기)
1. **조용한 실습망에서는 마지막 활동이 채점되지 않는다.**
   - tcpdump `-G`는 다음 패킷이 와야 파일을 바꾼다. nmap 뒤로 트래픽이 없어 그 파일이 열린 채 남았다. Claude가 배포 VM에서 Kali로 ping 1개를 보내 파일을 넘겼다(10:01).
   - 파일이 넘어가도 nmap 창(09:45)은 `capture_edge`였다. 캡처 경계를 패킷 시각 최댓값(09:49:49)으로 잡아, 창 끝(09:50)까지 관측했는지 알 수 없다고 본다(설계대로). 다음 파일(10:01 ping)이 들어온 작업 28에서야 `live`가 되어 사건에 붙었다.
   - 고칠 방향(안): 시간 기준 회전(`timeout`으로 tcpdump를 5분마다 다시 시작) + 캡처 경계를 "파일이 덮은 시간"(회전 시작\~끝)으로 기록.
2. **사건이 뒤로 늘어나도 보고서를 다시 쓰지 않는다.**
   - 사건 ID는 `캡처|자산|역할|시작 epoch`다. 09:40 창만으로 만든 사건(연결 2개)에 작업 27에서 보고서가 붙었고, 작업 28에서 nmap 창이 더해져 연결 103개가 됐지만 ID가 같아 에이전트가 "처리할 사건 0건"으로 건너뛰었다.
   - 지금 큐의 1·2위 보고서는 ping·curl 2건만 설명한다(nmap 없음).
   - 고칠 방향(안): 보고서를 만들 때 사건의 창 목록(또는 `last_end`·연결 수)을 기록하고, 달라지면 새 작업에서 보고서를 다시 만든다. 다시 알릴지(Slack)는 따로 정한다.

### 다음
- 두 문제 모두 사용자가 추천대로 승인했다(Q55·Q56, [DD-016](design-decisions/DD-016-lab-capture-coverage-and-report-refresh.md)). 문제 1은 열넷째 작업, 문제 2는 그다음.

## 열넷째 작업: 시간 기준 수집 회전과 관측 끝 시각(2026-11-18, DD-016 결정 1·2)

### 바꾼 것
- [scripts/capture_rotate.sh](../scripts/capture_rotate.sh)(새 파일): 시계의 `ROTATE_SECONDS` 경계마다 tcpdump를 멈추고 다시 시작한다. 다 쓴 파일은 `lab-<시작>-<끝>.pcap`(UTC)으로 수신 폴더에 넘기고, 패킷이 없는 파일은 버린다. `--immediate-mode -U`. SIGTERM이면 쓰던 파일을 마무리하고 끝낸다.
- [scripts/capture_lab.sh](../scripts/capture_lab.sh): 준비(폴더, 남은 파일 넘기기) 뒤 회전 스크립트를 zeekad·NET_RAW로 실행한다(tcpdump `-G`·`-z` 대신).
- [db/migrations/013_ingest_coverage.sql](../db/migrations/013_ingest_coverage.sql): `ingest_file.covered_from·covered_to`.
- [zeek_ad/ingest.py](../zeek_ad/ingest.py): `coverage_from_name`, `checked_coverage`(패킷이 덮은 시간 안에 있을 때만, 1초 여유). [zeek_ad/live_capture.py](../zeek_ad/live_capture.py): `day_files`가 `covered_to`를 읽고, 캡처 경계 끝은 `observed_until`(마지막 패킷과 관측 끝 중 늦은 쪽). 시작은 첫 패킷 그대로(Transformer 창 위치).
- 시험 5개 추가(이름 해석, 덮은 시간 검사, 경계 끝, 예전 규칙 유지). 전체 119개 통과. 이 PC DB에도 013 적용.

### VM 시험
- 별도 컨테이너(회전 20초·10초, 임시 폴더):
  - 빈 파일은 버리고, 패킷이 있는 파일만 이름대로 넘어갔다. `docker stop` 0.16초 안에 쓰던 파일을 마무리해 넘겼다.
  - 처음 판(`--immediate-mode -U` 없음)은 멈출 때 받은 6개 중 4개만 저장했다(멈추기 직전 ping이 사라짐). 추가 뒤 2/2.
  - ping 150회(0.2초 간격)를 10초 회전 네 파일에 걸쳐 보냈더니 경계 한 곳에서 ping 1쌍을 놓쳤다(틈 약 0.4초). DD-016 한계로 적었다.
- 실제 서비스: 이미지 다시 빌드, VM DB에 013 적용(`db_migrate.py`를 pipeline 컨테이너에서 owner 비밀번호만 넘겨 실행), `up -d`.
  - 10:39 배포 VM에서 ping 3회 → 10:40:00 경계에 `lab-20261118T103931Z-20261118T104000Z.pcap`(패킷 10개, 마지막 10:39:52)이 넘어갔다. 그 뒤 트래픽 없음.
  - 작업 31: **10:35 창이 `live`**(작업 30에서는 `capture_edge`). 캡처 경계 끝 = 10:40:00(`covered_to`). 다음 트래픽 없이 마지막 창이 채점됐다.
- 참고: 시험 ping(배포 VM → Kali)과 회전 시험이 실제 수집에도 들어가 `lab-20261118`에 작은 사건(10:00\~10:10)이 생겼다.

### 다음
- DD-016 결정 3·4는 열다섯째 작업.

## 열다섯째 작업: 늘어난 사건의 보고서 다시 만들기(2026-11-18, DD-016 결정 3·4)

### 바꾼 것
- [zeek_ad/agent_store.py](../zeek_ad/agent_store.py): `report_reason`, `incidents_to_report`. 사건마다 가장 최근 보고서 작업의 창 목록(`incident_window`)과 이 작업의 창 목록을 비교한다. 새 표·열은 없다.
- [scripts/live_agent.py](../scripts/live_agent.py): 처리할 사건 = 새 사건 + 창이 달라진 사건. 출력에 "새 사건 N, 늘어난 사건 M"을 적는다.
- [zeek_ad/slack.py](../zeek_ad/slack.py) `alerted_before`, [zeek_ad/agent_graph.py](../zeek_ad/agent_graph.py) `early_alert`·`deliver`, [zeek_ad/agent_pipeline.py](../zeek_ad/agent_pipeline.py): 다른 작업에서 이미 알린 사건은 Slack 기록을 건너뛴다.
- 시험: [tests/test_agent_store.py](../tests/test_agent_store.py)(5개), [tests/test_agent_graph.py](../tests/test_agent_graph.py)에 1개. 전체 125개 통과. 평가 동결 파일은 건드리지 않았다.

### VM 확인(작업 31)
- 고른 사건: 3건 모두 `changed`이고 모두 이미 알린 사건이었다(1위 10.10.0.10 responder 09:40, 2위 10.10.0.50 originator 09:40, 5위 10.10.0.10 originator 10:00).
- `live_agent.py --capture lab-20261118`: 3건 처리, 약 150초. LLM 보고서 3건 모두 검증 통과.
- 1·2위 보고서가 작업 31로 바뀌었다. 요약에 "연결 103건, 목적지 포트 102개, 100건 거부(REJ)"가 들어가 nmap을 설명한다(작업 27 보고서는 ping·curl만).
- `slack_delivery`: 작업 27·29·30 행만 있고 작업 31 행은 없다(다시 보내지 않음). 검토 요청은 생기지 않았다(판단 모델이 analyst_review를 고르지 않음).
- 확인할 때 worker 계정은 `dashboard` 뷰를 읽지 못해 같은 조인을 원래 표로 했다.

### 다음
- 장시간 시험 전에 리비전 정리 기능. 그다음 Kali 공격 시나리오와 해석.
- 대시보드 쪽에 알릴 것: Slack 기록은 보고서 작업이 아니라 사건 ID로 찾는다(DD-016 한계).

## 열여섯째 작업: 에이전트 사건별 실패 격리와 다시 시도(2026-11-18, 검토 Q57 결함 2)

### 문제
- [scripts/live_agent.py](../scripts/live_agent.py)의 1차·2차 반복에 예외 처리가 없었다. 한 사건이 실패하면 실행이 끝나 뒤 사건은 LLM 보고서·판단이 없었다.
- 다시 시도는 그날 새 파일이 와서 다시 계산이 성공해야 일어났다. 실습망이 조용하면 빈 채로 남았다.
- 보고서를 저장한 뒤 판단·전송에서 실패한 사건은 "보고서 있음"이라 다음 실행에서도 고르지 않았다.

### 바꾼 것
- `live_agent.run_two_phases`: 사건마다 예외를 잡아 기록하고 다음 사건으로 간다. 1차 실패 사건은 2차를 건너뛴다. 실패가 있으면 종료 코드 1.
- [zeek_ad/agent_store.py](../zeek_ad/agent_store.py) `report_reason`: 보고서 작업에 전송 판단(`send_decision`, 흐름의 마지막 쓰기)이 없으면 `retry`로 다시 고른다.
- [scripts/live_watcher.py](../scripts/live_watcher.py): 에이전트가 실패한 캡처를 기억해 새 파일 없이도 다음 주기에 다시 부른다. 설정 `agent_retries`(2)번까지. 새 다시 계산 뒤의 실패는 다시 센다. 기억은 감시 프로그램이 도는 동안만 있다.
- 시험 8개 추가: 사건별 격리 3개, 다시 시도 판단 2개, 감시 프로그램 다시 시도 2개, 실패한 LangGraph thread를 같은 thread_id로 처음부터 다시 시작 1개. 전체 133개 통과.

### VM 확인
- 이미지 다시 빌드, `up -d`. 컨테이너 안 시험 통과.
- `live_agent.py --capture lab-20261118`: 처리할 사건 0건(새 0, 늘어난 0, 다시 시도 0), 종료 코드 0. 작업 31 사건은 모두 판단까지 끝났다.
- 실제 실패를 일부러 일으키는 VM 시험은 하지 않았다(시험의 가짜 실패와 LangGraph 다시 시작 시험으로 확인).

### 다음
- 결함 1은 열일곱째 작업.

## 열일곱째 작업: LLM 보고서 응답 형식 검사(2026-11-18, 검토 Q57 결함 1)

### 문제
- `llm_report.final_report`는 응답이 SCHEMA 모양이라고 믿고 검증한다. `send_recommendation`이 빠지면 `KeyError`로 사건 처리가 멈췄다(재현). `limitations`가 문자열이면 글자 단위로 돌아 검증을 통과했다. 설계 9.1절은 "형식 오류면 템플릿"이다.
- `llm_report.py`는 평가 동결 파일이라 고치지 않는다(sha256 그대로 확인).

### 바꾼 것
- [zeek_ad/report_guard.py](../zeek_ad/report_guard.py)(새 파일): `schema_problems`(SCHEMA가 쓰는 type·properties·required·items·enum만 검사, 문제 문장에는 경로만 넣고 LLM 글은 넣지 않음), `guarded_final_report`(형식이 틀리면 응답을 없는 것으로 바꿔 `final_report`에 넘김 → 템플릿, reason `format: schema · …`. 검증 중 예외도 템플릿, reason `format: verify <예외 종류>`).
- [zeek_ad/agent_graph.py](../zeek_ad/agent_graph.py) `write_report`, [zeek_ad/agent_pipeline.py](../zeek_ad/agent_pipeline.py): `guarded_final_report`를 쓴다. DB `agent_report.llm_call`에는 LLM 원래 출력을 그대로 저장하고, 그래프 상태·전송 판단 비교·trace에는 검사한 기록을 쓴다(형식이 틀리면 LLM 의견 없음).
- 평가 배치 스크립트(`run_agent_reports.py`, 동결)는 그대로다. 실습망·LangGraph 경로에만 적용된다.
- 시험: [tests/test_report_guard.py](../tests/test_report_guard.py) 5개(형식 오류 6가지, 정상, 오류 문장, 검증 중 예외, 호출 실패). 전체 138개 통과.

### 확인
- 저장된 실제 Gemini 원래 출력 전부에 형식 검사를 돌렸다: 이 PC 66건, VM 75건 모두 형식 맞음(잘못 걸리는 응답 없음). 템플릿 2건은 형식이 아니라 숫자 검증 실패다.
- VM: 이미지 다시 빌드, 컨테이너 안 시험 통과, `live_agent.py` 정상 종료(처리할 사건 0건).

### 다음
- MLflow trace 예외 문장 문제(열여덟째 작업, 사용자가 결함 3보다 먼저 하기로 승인).

## 열여덟째 작업: MLflow trace에 예외 문장 남기지 않기(2026-11-18, Q57 후속)

### 문제
- `mlflow.start_span` 안에서 예외가 나면 MLflow가 오류 상태와 함께 예외 문장·stack trace를 span에 저장한다(설치된 3.17.2 문서와 실험으로 확인: 고치기 전 방식이면 IP가 trace에 남음).
- DB 오류 문장에는 `Key (job_id, incident_id)=(31, lab-…|10.10.0.10|…)`처럼 사건 ID(실제 IP)가 섞일 수 있다. 설계 9.2절 "민감한 원문을 trace에 넣지 않는다"에 어긋난다.
- 결함 2를 고쳐 실패가 사건별로 처리되면서 실패한 실행의 trace도 남게 되어 드러날 가능성이 커졌다.

### 바꾼 것
- [zeek_ad/agent_graph.py](../zeek_ad/agent_graph.py) `mark_failed`·`traced`: 노드 span 안에서 예외를 잡아 오류 상태와 `zeekad.error_type`(예외 종류)만 남기고, span을 닫은 뒤 원래 예외를 다시 던진다.
- [scripts/run_agent_graph.py](../scripts/run_agent_graph.py) `traced_run`: 사건 span(`incident_flow.*`)도 같은 방식. trace를 내보낸 뒤 예외를 다시 던지므로 `live_agent.py`의 사건별 실패 처리는 그대로다.
- 시험: [tests/test_trace_privacy.py](../tests/test_trace_privacy.py)(임시 SQLite MLflow 저장소에 실제 trace를 쓰고, IP·예외 문장이 없고 오류 상태·예외 종류만 있는지 확인). 전체 139개 통과.

### 확인
- 기존 trace 검사(IP 모양 글자, 전체 trace): 이 PC 9건, VM 27건 모두 없음. 오류 상태 trace도 0건이라 지울 것이 없다.
- VM: 이미지 다시 빌드, 컨테이너 안 시험 통과.

### 다음
- 결함 3은 열아홉째 작업.

## 열아홉째 작업: 처리 중 끊긴 수신 파일 이어 하기(2026-11-18, 검토 Q57 결함 3)

### 문제(끊긴 시점별)
- 옮기기 전: 파일이 수신 폴더에 남는다. 다음 주기에 같은 해시 기록이 있어 **중복으로 치워져 처리되지 않았다**(검토보다 나쁜 경우).
- 옮긴 뒤 Zeek 중: `received`로 남는다. `--retry-failed`는 `failed`만 본다.
- Zeek가 끝났는데 상태를 쓰기 전: 다시 돌리면 [run_zeek.py](../scripts/run_zeek.py)가 "출력 폴더가 이미 있다"로 거부한다.

### 바꾼 것([zeek_ad/ingest.py](../zeek_ad/ingest.py))
- 같은 해시 기록이 `received`면 중복이 아니라 끊긴 처리로 보고 이어서 처리한다.
- 캡처 ID·패킷 정보를 옮기기 **전에** 기록한다(옮긴 뒤 끊겨도 저장 폴더에서 찾을 수 있게).
- Zeek 출력 폴더가 이미 있으면 완성본으로 보고 `zeek_done`으로 기록한다(run_zeek.py는 임시 폴더 → 이름 바꾸기로 게시).
- `recover_stale`: `received`에 `stale_received_seconds`(600초) 넘게 머문 파일 중 저장 폴더에 있는 것을 이어서 처리한다. [scripts/live_watcher.py](../scripts/live_watcher.py)가 매 주기 부른다. 여유 시간은 다른 프로세스가 처리 중인 파일을 건드리지 않으려는 것이다.
- 시험 6개(끊긴 시점 세 가지, 수신 폴더 쪽 건너뜀, 옮기기 전 기록 순서, 끝난 파일은 여전히 중복). 전체 145개 통과.

### 확인
- 새 SQL(`make_interval`)을 이 PC·VM DB에서 실행: 대상 0건. 지금 멈춘 파일은 없다.
- VM `failed` 1건은 `lab-20261118-092057.pcap`(예전 `-G` 회전 때의 빈 파일, "패킷이 없는 파일")이라 이번 일과 무관하다.
- VM: 이미지 다시 빌드, 컨테이너 안 시험 통과, 감시 프로그램 정상 시작. 컨테이너를 처리 도중에 죽이는 VM 시험은 하지 않았다(시점을 맞추기 어렵다, 가짜 DB 시험으로 확인).

### 다음
- 결함 4와 문서 정리는 스무째 작업.

## 스무째 작업: 결함 4 기록과 문서 정리(2026-11-19, 검토 Q57)

- 결함 4: [zeek_ad/evaluation.py](../zeek_ad/evaluation.py) `pooled_hits` 설명에 한계를 적었다(여러 날 에피소드는 마지막 날 값으로 덮어씀). 정답 17건이 모두 하루짜리인지 `cic17-episodes.v1.json`의 규칙 캡처로 확인했다(여러 날 0건). 여러 날 에피소드를 어떻게 셀지는 평가 정의라 생길 때 결과를 보기 전에 정한다.
- [FINAL_PROJECT_DESIGN.md](../FINAL_PROJECT_DESIGN.md): "범위: 구현 시작 안 함"에 "확정 당시"를 붙이고 현재 상태 한 줄(세션 인계 링크, DD 우선)을 더했다. "그래프 모델 제외"에 DD-007 TGN으로 추가했다는 괄호를 더했다. 결정은 바꾸지 않았다.
- [session-handoff.md](session-handoff.md): "지금 위치"와 "남은 일"을 지금 상태로 다시 썼다(끝난 단계 4·5 항목과 지난 일정 정리, 자주 쓰는 명령 절 추가).
- [design-discussion-log.md](design-discussion-log.md): 같은 날 Q52가 둘이라 뒤의 uid 질문을 Q52b로 바꿨다. 다른 문서의 "Q52"는 비판적 검토를 가리킨다.
- AGENTS.md(로컬 작업 안내, 저장소에 없음): 시험 명령을 전체 시험(`python -m unittest discover -s tests`)으로 바꾸고, 표준 라이브러리만 쓰는 시험 명령은 설명으로 남겼다.
- 루트 `mlflow.db`: 실험 Default 1개, 실행·모델·trace 0건임을 읽기 전용으로 확인하고 scratchpad로 옮겼다. `.gitignore`에 `/mlflow.db`, `/mlruns/`를 더했다.
- 확인: 고친 문서 8개의 상대 링크 깨짐 없음, 시험 145개 통과(시험이 루트에 mlflow.db를 다시 만들지 않음).
- 하지 않은 것: pandas 3.1.0 정리(사용자가 미룸), README·git(포트폴리오 문서 단계).

### 다음
- 남은 일은 [세션 인계](session-handoff.md) 순서: 리비전 정리(스물한째 작업) → Kali 공격 시나리오 → 검토 결정 경로·알림 묶음 → 대시보드 Compose → 단계 7 → 포트폴리오 문서.

## 스물한째 작업: 리비전 정리(2026-11-19, DD-015 "배포 전에 할 일")

### 왜
- VM 실측: `lab-20261118` 리비전 7개가 584MB였다. 리비전 하나 84MB 중 84MB가 그래프(`graphs/tgn_v1`)다. 그래프가 월요일 이벤트 전체 + 그날 이벤트라 리비전마다 월요일 그래프를 다시 쓴다. 나머지(Zeek 합치기·Silver·Gold·이벤트)는 300KB 정도다. 같은 날 원본 PCAP은 724KB, 파일별 Zeek 출력은 1.9MB였다.
- 5분마다 파일이 오면 하루 리비전이 288개라 그래프만 20GB를 넘는다(디스크 60GB).
- DB는 33MB이고 실습망 작업 하나가 창 점수 36행을 더한다. DB의 옛 작업은 지우지 않는다. "늘어난 사건"(`incidents_to_report`)과 "이미 알린 사건"(`alerted_before`) 판단이 옛 작업의 보고서·Slack 기록을 읽는다(DD-016).

### 남기는 규칙([zeek_ad/live_capture.py](../zeek_ad/live_capture.py) `revisions_to_prune`)
- 리비전 폴더를 읽는 곳은 에이전트([live_agent.py](../scripts/live_agent.py))뿐이고, 최신 성공 작업의 리비전(Gold 위치)만 읽는다. 근거 API·대시보드는 DB만 읽는다.
- 새것의 기준은 이름의 파일 수다. 그날 파일은 늘기만 하므로 파일이 많을수록 나중 계산이다.
- 남긴다: 성공(`done`) 리비전 중 최신 `keep_revisions`개(기본 2), 가장 최신 성공보다 새로운 리비전 전부(계산 중이거나 실패 원인을 볼 것). 실패가 이어져도 마지막 성공 리비전은 남는다.
- 지운다: 나머지(오래된 성공, 최신 성공보다 오래된 실패·중단). 성공 리비전이 없으면 아무것도 지우지 않는다.
- 지운 리비전의 처리 기록(`pipeline.json`: 단계별 시간·작업 번호)은 `<runs_out>/<캡처 ID>/pruned.jsonl`에 한 줄씩 남긴다.

### 바꾼 것
- [live_capture.py](../zeek_ad/live_capture.py): `revisions_to_prune`, `prune_revisions(capture_dir, keep, dry_run)`. 리비전 이름 형식의 폴더만 보고, 심볼릭 링크는 따라가지 않는다.
- [live_recompute.py](../scripts/live_recompute.py): 성공한 뒤 그날 리비전을 정리한다. 정리가 실패해도 다시 계산은 성공으로 두고 경고만 출력한다. 실패한 다시 계산 뒤에는 정리하지 않는다.
- [prune_revisions.py](../scripts/prune_revisions.py): 손 실행용(`--dry-run`, `--capture`, `--keep`). 더 이상 파일이 오지 않는 지난 날짜는 자동 정리가 다시 돌지 않으므로 이것으로 정리한다.
- [configs/pipeline/live.v1.json](../configs/pipeline/live.v1.json): `"keep_revisions": 2`.
- 시험 5개([tests/test_live_capture.py](../tests/test_live_capture.py) `PruneRevisionsTest`: 최신 성공 keep개, 실패가 이어질 때, 오래된 실패·중단, 파일 수 숫자 비교, 폴더 정리·dry-run·기록). 전체 150개 통과.

### 확인
- 이 PC dry-run(`lab-20261201`): rev-0006(작업 21) 1개 지울 대상, rev-0007·0008 남음. 이 PC는 지우지 않았다.
- VM: 이미지 다시 빌드, 컨테이너 안 시험 통과. dry-run 결과가 예상과 같아서(rev-0001\~0005, 작업 25\~29) 실제로 정리했다. 436MB를 비워 `outputs/live/runs`가 584MB → 167MB가 됐다. `pruned.jsonl` 5줄.
- 정리 뒤 `live_agent.py --capture lab-20261118`: "작업 31, 리비전 rev-0007-f6b6fc73, 처리할 사건 0건", 종료 코드 0. DB의 작업 25\~31, 창 점수 168행, 보고서 9건은 그대로다.
- 확인하지 못한 것: 다시 계산이 성공한 뒤 자동으로 정리하는 경로는 VM에서 아직 돌지 않았다(같은 날 새 파일이 와야 한다). 다음 작업(Kali 공격 시나리오)에서 같은 날 파일이 여러 개 생기면 확인한다.

### 알아 둘 한계
- 날짜마다 리비전이 최대 `keep_revisions`개 남는다. 날짜 수만큼은 늘어난다(하루 약 170MB + 그날 데이터). 날짜 단위 보존 기한은 두지 않았다.
- 원본 PCAP(`data/live/store`)과 파일별 Zeek 출력(`outputs/live/zeek`)은 다시 계산의 입력이라 지우지 않는다. 지금은 둘을 합쳐 3MB 정도다. DoS 같은 대량 트래픽을 넣으면 다시 본다.

### 다음
- Kali 공격 시나리오와 결과 해석(인계 문서 남은 일 1번).

## 스물둘째 작업: Kali 공격 시나리오와 정상 배경 섞기(2026-11-19, DD-017)

### 준비
- [scripts/lab_scenario.sh](../scripts/lab_scenario.sh)(Kali): 5분 칸마다 활동 하나(ping 20회, `nmap -sT -p 1-1000`, `nmap -sV -p 1-200`), 각 칸은 경계 5초 뒤 시작, 시각을 `~/scenario-*.log`에 남긴다. 시작 시각 옵션(`bash lab_scenario.sh 04:25`)은 배경과 맞출 때 쓴다.
- Claude가 Kali를 직접 돌리지 않은 이유: Kali는 격리된 실습망에만 있다(DD-015). 배포 VM을 거쳐 SSH로 들어가면 그 조작 트래픽이 수집 카드로 지나가 시험 데이터에 섞인다. 이 WSL은 Windows 프로그램 실행(interop)이 꺼져 있어 VMware `vmrun`도 쓸 수 없다.
- 배경(DD-017): `outputs/lab_background/v1/` — 월요일 보류 구간 18:30\~19:05 UTC(A, 패킷 410,002)와 합성 정상(B, 4,200), 합계 414,202. 충실도 확인은 DD-017에 적었다.
- 재생 시험(04:00 UTC, 배경 첫 10초, 1,085패킷): 실패 0, MTU 9000 → 1500 복구, 수집기 파일 크기가 시험 PCAP과 같음(179,308바이트, 큰 프레임 포함 모두 캡처). 이 10초분은 `lab-20261119`의 04:00 창에 남는다(시험분으로 표시).

### 실행 1: 공격만(작업 32\~35, Kali 03:40\~03:55 UTC)
- 03:25 칸 패킷 10개는 사용자의 연결 확인(ping)이다. 첫 창이라 `capture_edge`로 큐에서 빠졌다.
- 창별 점수(배포 VM responder. Kali originator도 거의 같다, *는 임계값 이상):

  | 칸 | 활동 | tail_rarity_v2(5.55) | tgn_recon(9.90) | transformer_v2(1.26) |
  | --- | --- | ---: | ---: | ---: |
  | 03:40 | ping 20회 | 4.27 | 2.39 | 0.51 |
  | 03:45 | nmap -sT 1-1000 | 7.16* | 4.92 | 16.58* |
  | 03:50 | nmap -sV 1-200 | 7.16* | 11.74* | 16.26* |

- 큐(작업 35): 1위 10.10.0.50 originator 03:50\~03:55(꼽은 모델 TGN, 겹쳐 꼽음 꼬리·Transformer, 연결 169), 2위 10.10.0.10 responder 03:45\~03:55(꼬리, 겹쳐 꼽음 TGN·Transformer, 연결 1,169).
- LLM 보고서 4건(작업 34·35) 모두 검증 통과, 숫자가 관측과 맞다(예: "1000개 고유 목적지 포트, 1000건 중 999건 REJ"). 판단 모델은 모두 send, Slack은 dry-run 기록.
- 자동 리비전 정리 확인: 세 번째 리비전 성공 뒤 rev-0001(작업 32, 87MB)이 자동으로 지워졌다(스물한째 작업에서 확인하지 못했던 경로).
- 발견: Kali 사건 범위가 03:50부터라 `nmap -sT` 창(03:45)이 빠졌다. DD-009는 사건 범위를 꼽은 모델의 창으로 정하는데, 순위를 번갈아 놓는 결합에서 TGN(03:50만 꼽음)이 이 사건을 가져갔다. 사건 시작이 바뀌어 사건 ID가 달라졌고(작업 34의 03:45 사건 → 작업 35의 03:50 사건), 같은 공격자가 Slack에 다시 알려졌다(DD-016의 "이미 알린 사건"은 사건 ID 기준). 고칠 방향(겹친 모델 창의 합, 사건 ID를 첫 창에 묶지 않기)은 실행 2 결과와 함께 사용자 결정으로 올린다.

### 실행 2: 배경 + 공격(작업 36\~42, 최종 작업 42)
- 배경 재생 04:15:00\~04:50:36 UTC(배포 VM 컨테이너 `zeekad-replay`, 실패 0, MTU 복구). 35분 PCAP이 36초 늦게 끝났다(재생 지연 약 1.7%. 뒤 칸일수록 창 경계가 최대 36초 밀린다).
- Kali `bash ~/lab_scenario.sh 04:25`: 04:25 ping, 04:30 -sT, 04:35 -sV. 배경만 칸: 04:15·04:20·04:40·04:45. 04:50 칸은 재생 끝자락(36초).
- 처리: 에이전트 한 번에 최대 약 10분(사건 최대 52건) → 파일이 밀렸지만 다음 차례에 한꺼번에 계산해 따라잡았다. 리비전 정리는 매번 돌았다. 그날 보고서 61건(LLM 59건, 검증 통과 59건), Slack dry-run 사건 20건.
- 칸 × 그룹별 임계값을 넘은 단위 수(단위 = 자산×역할. 꼬리/TGN/Transformer):

  | 칸 | 활동 | A 월요일 재생(16단위) | B 합성 정상(3) | Kali(1) | 배포 VM(1) |
  | --- | --- | --- | --- | --- | --- |
  | 04:15 | 배경만 | 1/2/9 | 0/0/0 | — | 0/0/1 |
  | 04:20 | 배경만 | 1/5/2 | 0/0/0 | — | 0/0/1 |
  | 04:25 | ping | 0/2/3 | 0/0/0 | 0/1/0 | 0/1/1 |
  | 04:30 | nmap -sT | 2/2/1 | 0/**2**/0 | 1/0/1 | 1/1/1 |
  | 04:35 | nmap -sV | 0/3/0 | 0/0/0 | 1/0/1 | 1/0/1 |
  | 04:40 | 배경만 | 1/2/1 | 0/0/0 | — | 0/0/0 |
  | 04:45 | 배경만 | 2/0/1 | 0/0/0 | — | 0/0/1 |

- 공격(Kali): 두 스캔 칸 모두 꼬리 희귀도·Transformer가 잡았다(실행 1과 같다). TGN은 이번에는 ping 칸(10.22)을 꼽고 두 스캔 칸(6.78·7.92)은 꼽지 않았다. 실행 1과 반대라 TGN 판정은 실행마다 흔들린다(같은 날 앞 실행의 기억, 배경 이웃이 다르다). 큐: 배포 VM responder 04:30\~04:40 6위(연결 753), Kali originator 04:30\~04:40 7위(637).
- B(합성 정상, HTTP 서버 = 배포 VM): 배경만 칸 4개에서는 한 번도 꼽히지 않았고, **-sT 칸(04:30)에서만 TGN이 B 3단위 중 2개를 꼽았다**(10.10.0.11 originator 10.64). 스캔당하는 서버와 통신해서 생긴 그래프 이웃 전파다. 11-17 파일 시험의 관찰을 실제 수집 경로에서, 공격 전후 대조 칸과 함께 다시 확인했다. 배포 VM은 배경만 칸(04:15·04:20·04:45)에서도 Transformer가 꼽았다(평소 없던 HTTP 서버 역할이 생겼다).
- A(월요일 재생): 같은 35분을 원래 배치 점수(outputs/eval의 CIC 실행)와 단위별로 맞춰 비교했다(112단위 = 16단위 × 7칸).

  | 모델 | 배치 후보 | 실습망 후보 | 둘 다 | 첫 칸(04:15) 배치/실습망 | 첫 칸 뺀 나머지 배치/실습망 | 점수 순위 상관(첫 칸 제외) |
  | --- | ---: | ---: | ---: | --- | --- | ---: |
  | tail_rarity_v2 | 7 | 7 | 3 | 0/1 | 7/6 | 0.83 |
  | tgn_recon | 10 | 16 | 3 | 2/2 | 8/14 | 0.71 |
  | transformer_v2 | 6 | 16 | 4 | 1/8 | 5/8 | 0.70 |

  - 배치에서도 같은 트래픽의 5\~9%가 후보다(임계값이 월요일 보류 p95라 설계상 약 5%).
  - 꼬리 희귀도(창 하나의 특징)는 비율이 같고 순위도 가장 비슷하다. 후보가 정확히 겹치는 것은 3개다(재생 지연으로 창 경계가 밀린 몫이 있다).
  - Transformer는 첫 칸에서 8/15를 꼽았다(배치 1/15). 재생이 갑자기 시작돼 자산마다 앞 창 이력이 없다(원래는 그 전 6시간이 있었다). 첫 칸을 빼면 8/97 대 5/97로 가깝다.
  - TGN은 첫 칸 뒤에도 14/97 대 8/97로 많다. 실습망 하루 그래프에서 A 자산은 기억이 비어 있는 새 노드다(같은 행동이 월요일 원래 그래프에는 192.168.10.x로 있다).
  - 큐 1위는 A 10.10.0.102 originator 04:35\~04:45(세 모델 모두, 연결 2,462)다. 원래 192.168.10.5인데, 배치에서도 같은 시점(실습망 04:40·04:45에 해당)을 꼬리 희귀도 6.06·6.47, TGN 11.07로 꼽았다. 실습망이 만든 오탐이 아니라 월요일에도 드문 정상 창이다.
- 04:00 재생 시험(10초)은 사건 15건 정도를 만들었다(5분 창에 10초만 있는 창). 시험분이라 해석에서 뺀다. 잠깐만 나타난 자산은 이상하게 보인다는 성질은 남겨 둔다.
- 결합 규칙(Q59): 사건이 늘어 큐 순서가 바뀌자 실행 1의 Kali 사건 범위가 03:50\~(TGN) → 03:45\~03:55(Transformer·꼬리)로 다시 바뀌었다. 사건 범위가 큐 구성에 따라 흔들린다. 이 사건 ID는 작업 34에서 알렸으므로 다시 보내지 않았다.

### 시연에서 주장할 문장(Q52 4번. 2026-11-19 사용자 확인, 3번은 "Kali 쪽"으로 범위를 좁힘)
- 용어: "배포 경로"라고 쓰지 않고 "VM에서 실시간으로 도는 처리"로 풀어 쓴다(사용자 결정, 2026-11-19). 비교 대상은 모델을 만들 때 CIC 하루치를 한꺼번에 처리한 "배치 처리"다.
1. VM에서 실시간으로 도는 처리(수집 → Zeek → 다시 계산 → 세 모델)는 같은 정상 트래픽(CIC 월요일 보류 35분 재생)에 배치와 비슷한 점수를 낸다. 창 단위 순위 상관 0.70\~0.83이고, 꼬리 희귀도는 이상 판정 비율까지 같다(6%).
2. 다른 점도 측정했다. Transformer는 자산 이력이 없는 첫 창에서, TGN은 새 노드 문맥에서 이상 판정이 는다. 실습망 점수는 CIC 월요일 기준과의 차이로 읽는다.
3. Kali 포트 스캔(nmap -sT 1,000포트, -sV)은 정상 배경이 있든 없든 꼬리 희귀도·Transformer가 매번 잡았다. ping은 Kali 쪽에서 두 모델 모두 잡지 않았다. 사건 보고서의 숫자(포트 수, 거부 수)는 관측과 맞았다.
4. TGN은 스캔당하는 서버와 통신한 정상 클라이언트를 스캔하는 칸에서만 함께 꼽았다(앞뒤 배경 칸에서는 0). 그래프 이웃 전파의 효과이자 한계다.
5. 결합 큐는 조사 순서이지 판정이 아니다. 이번 큐 1위는 공격이 아니라 월요일에도 드물었던 정상 창이었고, 공격 사건은 6·7위였다.
- 3번 범위를 좁힌 이유: 실행 2에서 배포 VM(받는 쪽)의 ping 칸(04:25)은 Transformer가 꼽았다(2.80). 그 자산은 ping이 없던 배경 칸(04:15·04:20)에서도 이미 꼽혔다(합성 정상 클라이언트의 HTTP를 받는 서버 역할이 새로 생김). ping 때문이라고 볼 수 없어 문장에서 뺐다.
- 5번은 결합 v2(작업 44)에서도 같다(1위 재생 자산, 배포 VM 6위, Kali 7위).

## 스물셋째 작업: 결합 v2 — 겹친 사건 합치기(2026-11-19, DD-018)

- 사용자 결정(Q59 후속): 추천대로 고친다. 시연 문장의 "배포 경로"는 "VM에서 실시간으로 도는 처리"로 풀어 쓴다(스물둘째 작업 문장 초안에 반영).
- 확인한 것: VM에서 등록 모델을 불러온 뒤에도 `zeek_ad.fusion`은 컨테이너 코드(`/app/zeek_ad/fusion.py`)다. 결합 설정만 묶음에서 읽는다. 그래서 v1 코드 동작은 그대로 두고, 새 설정의 `overlap_policy`로만 켠다.
- 바꾼 것: [configs/models/fusion.v2.json](../configs/models/fusion.v2.json)(v1 파일은 그대로), [zeek_ad/fusion.py](../zeek_ad/fusion.py) `fuse`·`fuse_merge_overlaps`·`picked_score`, [zeek_ad/bundle.py](../zeek_ad/bundle.py) `build_queue`(설정의 `overlap_policy`, 없으면 skip), [zeek_ad/worker.py](../zeek_ad/worker.py) `write_results`(`model_score` = `picked_score`, v1은 값이 같다). 시험 5개 추가, 전체 161개 통과.
- 실습망 작업으로 다시 계산: v1 결과가 DB 작업 34·35·42와 같다(42는 사건 52개의 ID·순위·출처·모델 점수까지). v2에서는 작업 35의 Kali 사건이 03:45\~03:55가 되고 ID가 작업 34와 같아진다(다시 알림 없음). 작업 42는 사건 수 그대로, 배포 VM 사건이 04:15\~04:40으로 길어진다(Transformer가 배경·ping 칸에서 꼽은 창이 합쳐짐).
- 아직 VM에 반영하지 않았다. 결합 v2 설정을 담은 묶음을 등록 모델의 새 버전으로 올리고 alias를 바꾸는 일은 단계 7(모델 교체·롤백 시연)에서 함께 한다.

## 스물넷째 작업: 분석가 검토 결정 경로(2026-11-19, DD-019, Q50 2번)

- 사용자 결정: Q50 원안(API가 흐름 재개) 대신 "DB 함수로 결정을 받고 파이프라인이 재개"(Claude 추천). API는 읽기 전용 그대로다.
- 바꾼 것
  - [db/migrations/014_review_decision.sql](../db/migrations/014_review_decision.sql): `analyst_review.resumed_at·resume_error`, 함수 `dashboard.decide_review`(dashboard_rw·worker만 실행), 검토 목록 뷰에 두 열.
  - [db/migrations/015_review_backfill.sql](../db/migrations/015_review_backfill.sql): 014 전에 결정된 검토를 재개됨으로 표시(아래 "발견").
  - [zeek_ad/review_resume.py](../zeek_ad/review_resume.py), [scripts/resume_reviews.py](../scripts/resume_reviews.py), [scripts/live_watcher.py](../scripts/live_watcher.py)(결정된 검토가 있을 때만 재개 스크립트를 부름), [zeek_ad/agent_graph.py](../zeek_ad/agent_graph.py)(재개 때 결정 시각을 덮지 않음).
  - 시험 6개([tests/test_review_resume.py](../tests/test_review_resume.py), 실제 LangGraph interrupt → 재개 포함). 전체 167개 통과.
- 이 PC DB: 014·015 적용, 함수 규칙을 되돌리는 트랜잭션 안에서 확인(정상, 두 번째 결정·잘못된 값·분석가 없음·요청 없음 거부, `zeekad_api`는 `42501`).
- 배포 VM
  - 이미지를 먼저 올려 감시 프로그램이 새 열을 찾지 못해(`UndefinedColumn`) 재시작을 반복했다. 일회용 컨테이너로 014를 적용해 풀었다. 배포 순서(migration 먼저)를 DD-019에 적었다.
  - 발견: 014 직후 감시 프로그램이 예전에 명령줄로 결정·재개한 CIC 작업 4의 시험 검토 2건을 "결정됐지만 재개 안 됨"으로 보고 재개를 시도해 `not_waiting`으로 남겼다. 014 전에는 재개해야만 결정이 기록됐으므로 015로 재개됨 표시를 했다.
  - 결정 전 검토 9건이 모두 재생한 정상 자산(DD-017 A)이었다. 판단 모델은 Kali·배포 VM 사건에는 send를 골랐고, 재생 정상 자산 일부를 분석가 검토로 보냈다.
  - 시연: 작업 41의 1위(A 자산)를 `dashboard_rw`로 `dismiss`(06:09:42) → 06:09:47 재개 → open → investigating → closed(false_positive), 이력 actor `demo-analyst`·reason은 메모, Slack 상태 알림 2건(dry-run), MLflow trace. 결정 전 검토 8건이 남았다.
- [데이터 계약 v2](data-contract-v2.md): "쓰기: 분석가 검토 결정" 절, 검토 목록 뷰 두 열, 알려진 빈칸 1번 해결 표시.

## 스물다섯째 작업: 같은 자산 알림 묶음(2026-11-19, DD-010 결정 5)

- 세부 해석(관측 시각 기준, 60분 묶음이 밀려감, 스레드 답글, 30분마다 채널 재알림, 머리 사건 종료면 새 알림)은 [DD-010](design-decisions/DD-010-ecs-enrichment-incident-lifecycle.md) "구현" 절에 적었다.
- 바꾼 것: [zeek_ad/slack.py](../zeek_ad/slack.py) `group_alert`·`alert_thread`·`record_delivery`, [configs/agent/slack.v2.json](../configs/agent/slack.v2.json)(LangGraph가 쓴다, [run_agent_graph.py](../scripts/run_agent_graph.py) `resources`), [db/migrations/016_slack_threads.sql](../db/migrations/016_slack_threads.sql). 시험 10개([tests/test_slack.py](../tests/test_slack.py)). 전체 177개 통과.
- 발견하고 고친 것: 처음에는 사건의 "첫 알림"을 기록 시각 순서로 골랐다. 같은 트랜잭션에서 기록하면 시각이 같아 머리 사건의 뒤 알림(자기 자신이 부모)이 첫 알림으로 잡혀 재알림을 놓쳤다(이 PC DB 확인에서 B가 False). 사건마다 "자기 자신이 아닌 부모"와 "재알림 여부"를 모아 보도록 바꿨다.
- 이 PC DB(되돌리는 트랜잭션, 알림 기록이 없던 CIC 자산 하나의 사건 5개, 17:30\~18:45): A 머리 → B(35분 뒤) 재알림 → C·D 답글 → E(B에서 35분 뒤) 재알림. 템플릿 뒤 LLM 보고서 알림은 모두 같은 스레드.
- 실습망 2026-11-19 알림 모의: 사건 알림 20건 → 채널 17건(새 14, 재알림 3), 조용한 답글 3건. Kali의 실행 2 공격(04:30)은 실행 1 묶음(03:45)의 답글 + 재알림이 된다(공격자가 다시 옴). 이날 알림 대부분은 서로 다른 재생 자산이라 자산 단위 묶음으로는 줄지 않는다.
- 배포 VM: 이번에는 migration을 먼저 적용(일회용 컨테이너) → `up -d`. 감시 프로그램 정상, 컨테이너 안 시험 통과. 실제 묶음 기록은 다음 실습망 트래픽 때 확인한다.
