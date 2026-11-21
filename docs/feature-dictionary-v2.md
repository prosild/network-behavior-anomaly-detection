# Gold 특징 사전 v2 (`conn-features.v2`)

v1 18개 특징([feature-dictionary-v1.md](feature-dictionary-v1.md))에 Zeek 프로토콜 로그 특징 24개를 더한 42개다. [DD-006](design-decisions/DD-006-behavior-detectors-reduced.md) 수정 절 1번이다. 화\~금 결과를 본 뒤 추가했다(결과 노출 이후의 변경).

## 만드는 법

- 입력: TGN 이벤트 표(`outputs/events/tgn_v1`). Silver conn 한 행에 run-02 프로토콜 로그 요약이 `uid`로 붙어 있다.
- 키: v1과 같은 `(capture_id, asset_id, role, window_start)`. 역할 펼치기와 창 배정 규칙도 같다.
- 코드: [zeek_ad/log_features.py](../zeek_ad/log_features.py), [scripts/build_gold_v2.py](../scripts/build_gold_v2.py) → `outputs/gold/conn_features_v2/`.
- **없으면 0이다.** 모든 로그 특징은 개수 또는 최댓값이다. 그 창에 해당 로그가 없으면 0이다. 비율은 쓰지 않는다. 분모(그 로그가 있는 연결 수)가 0인 창이 많기 때문이다.
- 역할별로 센다. 예: `ssh_auth_fail_count`는 originator 창이면 보낸 SSH 인증 실패, responder 창이면 받은 실패다.
- 모델 전처리: 24개 모두 log1p 대상이다(비율이 아니므로). 결측이 없어 중앙값 대치는 쓰이지 않는다.

## 로그 특징 24개

| 로그 | 이름 | 정의 |
| --- | --- | --- |
| dns | `dns_query_count` | dns.log 행 수 합 |
| | `dns_unique_query_count` | 서로 다른 질의 이름 수(연결마다 첫 질의) |
| | `dns_query_len_max` | 질의 이름 길이 최댓값 |
| | `dns_query_entropy_max` | 질의 이름 문자 엔트로피(bit) 최댓값. `tgn_data.entropy`와 같은 식 |
| | `dns_nxdomain_count` | NXDOMAIN 응답 수 |
| | `dns_rare_qtype_count` | 질의 유형이 A·AAAA·PTR이 아닌 연결 수 |
| http | `http_request_count` | http.log 행 수 합 |
| | `http_error_count` | 상태 코드 400 이상 수 |
| | `http_uri_len_max` | URI 길이 최댓값 |
| | `http_uri_special_max` | URI에서 특수 문자(`' " < > % ; ( ) { }`, `--`)가 차지하는 길이 비율의 최댓값 |
| | `http_user_agent_count` | 서로 다른 User-Agent 수 |
| | `http_host_count` | 서로 다른 Host 수 |
| ssl | `ssl_conn_count` | ssl.log가 있는 연결 수 |
| | `ssl_sni_count` | 서로 다른 SNI 수 |
| | `ssl_no_sni_count` | SNI가 없는 SSL 연결 수 |
| | `ssl_not_established_count` | 핸드셰이크가 끝나지 않은 SSL 연결 수 |
| ssh | `ssh_auth_fail_count` | `auth_success = false`인 연결 수 |
| | `ssh_auth_attempts_sum` | 인증 시도 수 합 |
| ftp | `ftp_fail_count` | 530 응답 수 합(USER 단계 포함) |
| Windows | `smb_map_count` | smb_mapping 행 수 합 |
| | `smb_file_count` | smb_files 행 수 합 |
| | `dce_op_count` | dce_rpc 행 수 합 |
| | `krb_fail_count` | Kerberos 실패 수 합 |
| | `ntlm_fail_count` | NTLM 실패 수 합. CIC 다섯 날 모두 0이다(합성 주입 대비로 둔다) |

## 검사

- 행 수가 v1과 같고(8,277), 키가 유일하다. 로그 특징에 null이 없다.
- 창마다 이벤트 표의 역할 행 수가 v1 `conn_count`와 같다. 같은 연결 집합이라는 뜻이다.
- 독립 재계산: 무작위 6창 + 희소 특징 최댓값 창 5개에서 pandas로 22개 특징을 다시 계산했다. 242개 값이 모두 같다.
