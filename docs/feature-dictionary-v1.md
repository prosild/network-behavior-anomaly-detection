# Gold 특징 사전 v1 (`conn-features.v1`)

기준: [최종 설계](../FINAL_PROJECT_DESIGN.md) 3.2·3.3·4.2절. 초안 작성일 2026-11-05.

## 행 단위와 키

- **한 행:** `(capture_id, asset_id, role, window_start)`. 연결이 하나라도 있는 창만 행이 된다.
- **창:** `window_start = floor(write_ts / 300) * 300`, `window_end = window_start + 300`. 반열린 구간이다.
- **창 라벨 `split`:** `windows.label_window`가 정한다.
  - 월요일: `train`, `holdout`, `split_boundary`, `capture_edge` 중 하나.
  - 다른 날: 용도 이름(`development`, `retrospective_eval`) 또는 `capture_edge`.
- **입력 연결:** 각 행에 Silver의 `processing_run_id`를 남긴다. 근거를 조회할 때는 같은 키로 Silver 역할 행을 다시 찾는다.
- **모델에 넣지 않는 것:** `asset_id`(IP 원문), `capture_id`, 시각, `split`. 모델에 넣는 범주는 `role`뿐이다(설계 3.3절).

## 관점

역할별로 자산 관점 열을 쓴다([role_windows.py](../zeek_ad/role_windows.py)의 `PERSPECTIVE`).
- `out_*`: 자산이 보낸 것. `in_*`: 자산이 받은 것.
- `peer_h`, `peer_p`: 상대 주소와 상대 포트. originator면 `resp_h`·`resp_p`, responder면 `orig_h`·`orig_p`다.

## 저장 원칙

- Gold에는 **변환 전 값**을 저장한다.
  - `log1p` 변환과 결측 대치는 모델 전처리에서 한다. 전처리는 학습 구간에서만 적합하고, 모델과 함께 버전을 관리한다(설계 6.1·8절).
- **결측과 0을 섞지 않는다.**
  - 측정 사실: `duration`·`orig_bytes`·`resp_bytes`는 항상 함께 없거나 함께 있다. 5일 37,121행이 셋 다 결측이다.
  - 결측 연결은 합계·분위수에서 빠진다. 결측 비율은 따로 남긴다.
  - 창의 모든 연결이 결측이면 합계·분위수는 null이다. 0이 아니다.
- **비율의 분모는 그 창의 연결 수**(`conn_count` ≥ 1)다. 그래서 분모가 0인 경우가 없다.

## 특징 18개

| 특징군 | 이름 | 정의 | 결측 처리 |
| --- | --- | --- | --- |
| 활동량 | `conn_count` | 연결 수 | 없음 |
| | `out_bytes_sum` | `out_bytes` 합 | 결측 연결 제외. 모두 결측이면 null |
| | `in_bytes_sum` | `in_bytes` 합 | 위와 같음 |
| | `out_pkts_sum` | `out_pkts` 합 | 결측 없음(측정) |
| | `in_pkts_sum` | `in_pkts` 합 | 결측 없음(측정) |
| 상대 다양성 | `peer_count` | 고유 `peer_h` 수 | 없음 |
| | `peer_port_count` | 고유 `peer_p` 수 | 없음 |
| 연결 상태 | `tcp_ratio` | `proto = tcp` 비율 | |
| | `udp_ratio` | `proto = udp` 비율 | |
| | `icmp_ratio` | `proto = icmp` 비율. 나머지(`unknown_transport`, 5일 97행)는 세 비율 어디에도 들지 않는다 | |
| | `unestablished_ratio` | `conn_state`가 S0, REJ, RSTOS0, RSTRH, SH, SHR, OTH 중 하나인 비율. 연결이 정상으로 성립하지 않은 상태들이다 | |
| | `rejected_ratio` | `conn_state = REJ` 비율. 거절 | |
| 지속시간 | `duration_p50` | 관측된 `duration`의 중앙값 | 결측 제외. 모두 결측이면 null |
| | `duration_p95` | 관측된 `duration`의 95% 분위수 | 위와 같음 |
| | `duration_missing_ratio` | `duration`이 결측인 연결 비율. 바이트 결측 비율과 같다 | 없음 |
| 서비스 구성 | `dns_ratio` | Zeek가 `service`에 `dns`를 붙인 연결 비율. 포트 53이라는 이유로 세지 않는다 | |
| | `service_unidentified_ratio` | `service`가 없는(미식별) 연결 비율 | |
| | `non_dns_conn_count` | `dns`가 아닌 연결 수. 미식별 포함 | |

- **분위수:** 근사가 아니라 정확한 분위수(Spark `percentile`, 선형 보간)를 쓴다. 손계산(numpy 기본값)과 대조할 수 있다.
- **`service` 값:** 쉼표로 여러 개가 붙을 수 있다(5일 2,117행). `dns` 판정은 쉼표로 나눈 목록에 `dns`가 있는지로 한다. 측정상 `dns`가 붙은 행은 모두 값이 `dns` 하나였다.

## 진단 열(모델 입력 아님)

- `eof_candidate_count`: 창 안의 `eof_candidate` 연결 수. DD-003.
- 긴 연결 점유율(설계 4.3절)은 단계 3의 진단에서 Silver 역할 행으로 계산한다.

## 과거 계산과의 차이

과거 탐색 코드(`historical/.../an7.py`)와 비교한다.
- **responder의 상대 포트:** 과거에는 `resp_p`를 썼다. v1은 `orig_p`를 쓴다(체크리스트 2.3절).
- **duration 결측:** 과거에는 0으로 바꿨다. v1은 결측으로 두고 비율을 따로 남긴다.
- **새로 추가한 특징:**
  - `icmp_ratio`
  - `rejected_ratio`
  - `duration_missing_ratio`
  - `service_unidentified_ratio`
