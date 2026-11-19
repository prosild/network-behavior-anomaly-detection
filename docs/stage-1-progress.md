# 단계 1 진행 기록

시작일: 2026-11-03, Asia/Seoul. 기준은 [최종 설계](../FINAL_PROJECT_DESIGN.md) 10절 단계 1과 [체크리스트](../IMPLEMENTATION_CHECKLIST.md) V1·V2·V4다. 단계 0의 결과는 [단계 0 진행 기록](stage-0-progress.md)에 있다.

## 첫 작업: Zeek 실행 환경 고정

### 1단계, 이미지 확인

과거 검증의 실행 설정은 Zeek 8.0.10, 이미지 `zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3`, 실행 `zeek -C -r <pcap> ext.zeek`였다(과거 자료(로컬 백업, 저장소에 없음)).

- Claude 관측: Docker 엔진 29.8.2. 로컬에 `zeek/zeek:8.0.10`과 `zeek/zeek:lts`가 있고, 두 태그 모두 위 digest를 가리킨다.
- 사용자 실행(2026-11-03):

```bash
docker image inspect zeek/zeek:8.0.10 --format '{{.Id}}'
docker run --rm zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3 zeek --version
```

- 결과: 이미지 ID가 기록된 digest와 같다. `zeek version 8.0.10`.
- 실행할 때는 태그가 아니라 digest로 지정한다. 태그(`lts` 등)는 나중에 다른 이미지를 가리킬 수 있다.

### 2단계, 작은 PCAP 샘플

월요일 원본에서 파일 순서상 1~400,000번째 패킷을 그대로 남겼다. 시간 범위로 자르지 않은 이유는 원본이 시간순으로 정렬돼 있지 않기 때문이다.

```bash
editcap -r CIC-IDS-2017/PCAPs/Monday-WorkingHours.pcap outputs/samples/monday-head-400k.pcapng 1-400000
TZ=UTC capinfos -M -c -s -a -e -u -o outputs/samples/monday-head-400k.pcapng
sha256sum outputs/samples/monday-head-400k.pcapng
```

| 항목 | 결과(사용자 실행, 2026-11-03) |
| --- | --- |
| 도구 | editcap·capinfos 4.2.2 |
| 패킷 수 | 400,000 |
| 크기 | 435,036,756 bytes |
| 가장 이른 시각(UTC) | 2017-07-03 11:55:58.598308. 원본 월요일의 최소 시각과 같다 |
| 가장 늦은 시각(UTC) | 2017-07-03 12:15:02.521274 |
| 길이 | 1,143.922966초, 약 19분 |
| 시간순 정렬 | False. 샘플 안에도 시각 역전이 있다 |
| SHA-256 | `67ac86efeb9e0b67f00d0d1b0aafdd66cd950441aee842510bd073518bb18fbe` |

- 5분 창으로 보면, 완전한 창은 `[12:00, 12:05)`, `[12:05, 12:10)`, `[12:10, 12:15)` 세 개다.
- `[11:55, 12:00)`과 `[12:15, 12:20)`은 캡처 경계에 걸린 불완전한 창이다.
- capinfos의 "가장 늦은 시각"은 시각의 최댓값이다. 파일 순서상 마지막 패킷의 시각이라는 보장은 없다.

### 3단계, 샘플로 첫 Zeek 실행

새 Zeek 스크립트 [configs/zeek/write-ts.zeek](../configs/zeek/write-ts.zeek)를 만들었다. JSON 출력과 `_write_ts` 확장이 들어 있고, 과거 `ext.zeek`와 동작이 같다. Claude가 `zeek -a`로 문법을 검사했다.

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/outputs/samples:/pcap:ro" -v "$PWD/configs/zeek:/zeek-scripts:ro" \
  -v "$PWD/outputs/zeek/monday-head-400k/run-01:/out" -w /out \
  zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3 \
  zeek -C -r /pcap/monday-head-400k.pcapng /zeek-scripts/write-ts.zeek
```

결과(사용자 실행, 2026-11-03):
- 로그 21종: analyzer, conn, dce_rpc, dns, files, ftp, http, kerberos, ldap, ldap_search, ntlm, ntp, ocsp, packet_filter, pe, smb_files, smb_mapping, ssh, ssl, weird, x509.
- `conn.log` 8,758행. 전체 로그 합계 33,392행(Claude 확인).

첫 conn 행과 해석:
- 내용: `192.168.10.5:49188 → 8.254.250.126:80`, `conn_state=SHR`, `history=^f`, `orig_pkts=0`, `resp_pkts=8`.
- `ts`는 11:55:58.598308로 캡처의 첫 시각이다. `_write_ts`는 약 5.7초 뒤다.
- 캡처가 연결 도중에 시작돼 서버 쪽 패킷만 보였다. `^`는 Zeek가 포트 등을 근거로 출발·수신 방향을 뒤집었다는 표시다.
- 캡처 경계의 불완전 연결 예다(설계 4.3절).

Claude 관측:
- conn의 `_write_ts` 최댓값은 1499084102.521274다. 샘플의 가장 늦은 패킷 시각(12:15:02.521274)과 같다. PCAP 끝에서 남은 연결을 기록할 때 마지막 패킷 시각이 쓰인 것으로 보인다. 다만 종료 플러시 판정은 V2에서 따로 한다.
- `packet_filter.log`의 `ts`는 1793694125.455309, 즉 실행한 날의 벽시계 시각이다. `_write_ts`는 0.0이다. 패킷을 처리하기 전에 기록된 행이다. 실행마다 바뀌는 값이 로그에 들어간다는 뜻이다.

### 4단계, 같은 설정 재실행 비교(V1)

같은 명령으로 `run-02`를 만들어 `run-01`과 비교했다(사용자 실행, 2026-11-03).

| 비교 | 결과 |
| --- | --- |
| `conn.log` SHA-256 | 다름. `b78b0c5f…` 대 `fd3075c2…` |
| 행 수 | 둘 다 8,758 |
| `uid`를 뺀 내용, 순서 포함 | **다름** |
| `uid`를 뺀 내용, 순서 무시 | 같음 |

Claude 추가 분석:
- 순서가 다른 곳은 `_write_ts` 묶음 2,967개 중 하나뿐이다. 마지막 묶음인 `_write_ts=1499084102.521274`(12:15:02.521274, 샘플의 마지막 패킷 시각)의 800행이다.
  - 이 묶음 안에서 274개 위치의 행 순서가 다르다.
  - `_write_ts` 값의 순서 자체는 두 실행이 같다.
- 해석: PCAP 끝에서 아직 열려 있던 연결 800개를 한꺼번에 기록할 때, Zeek는 연결 표를 순회한다. 순회 순서는 실행마다 새로 정하는 무작위 seed의 영향을 받는다. 그 외 연결은 패킷 처리 순서대로 기록되므로 순서가 같다.
- 영향:
  - 창별 집계(합·개수·분위수)는 행 순서와 무관하다. 그래서 특징 값은 같다.
  - 설계 4.2절의 동률 보조 키 `source_row_number`는 한 실행 안에서는 결정적이다. 하지만 seed를 고정하지 않으면 재실행 사이에서 같은 행을 가리키지 않는다. 체크리스트 V2의 "같은 시각 여러 행: 보조 키로 재실행 시 결정적 결과" 항목에 대한 반례다.
  - `uid`도 실행마다 바뀐다. 설계가 실행 간 대응에 UID를 쓰지 않기로 한 이유와 맞는다.

seed 고정 시험(Claude, scratchpad에서 실행):
- `run-03`은 `--save-seeds`로 seed를 저장했고, `run-04`는 `--load-seeds`로 같은 seed를 불러왔다.
- 결과: 로그 21종 중 20종이 바이트 단위로 같다. `conn.log`의 `uid`와 순서까지 같다.
- 다른 하나는 `packet_filter.log`다. 실행 시각(벽시계)이 들어가기 때문이다.

결정(최소 변경):
- v1 Zeek 실행 설정에 프로젝트 고정 seed 파일을 추가한다. 실행 manifest에 seed 파일과 그 해시를 기록한다.
- 설계 계약은 바꾸지 않는다. 실행 간 대응은 계속 자연 키로 한다. Zeek 버전·설정이 바뀌면 seed가 같아도 출력이 달라질 수 있기 때문이다.
- `packet_filter.log`는 재현 비교 대상에서 뺀다.

### 5단계, 프로젝트 seed 파일과 재현 확인

- `run-03`은 `--save-seeds`로 [configs/zeek/seeds.v1.txt](../configs/zeek/seeds.v1.txt)를 만들며 실행했다. `run-04`는 `--load-seeds`로 그 파일을 불러와 실행했다(사용자 실행, 2026-11-03).
- `conn.log` SHA-256은 두 실행 모두 `f3278aa348062dddd0edeb88949a38983f46e0396e4613a799586681c38dc829`다.
- 로그 21종 중 20종이 바이트 단위로 같다. 다른 하나는 `packet_filter.log`다.
- seed 파일 SHA-256: `ecdd0e2805335169651da0323e51db322e7a92184d232c75a8fd689bcfc2890e`.
- 같은 PCAP·이미지·스크립트·seed이면 재실행 결과가 같다는 것을 확인했다(V1의 작은 재실행 재현).

### 6단계, 실행 스크립트와 실행 manifest

- [configs/zeek/run.v1.json](../configs/zeek/run.v1.json): 이미지 digest, Zeek 8.0.10, `-C`, 스크립트, seed 파일, 비교 제외 로그.
- [scripts/run_zeek.py](../scripts/run_zeek.py):
  - 설정대로 docker를 실행한다.
  - 출력 폴더에 `run-manifest.json`과 `zeek.stderr.txt`를 남긴다.
  - `<out>.tmp`에 완성한 뒤 이름을 바꿔 게시하고, 이미 있는 출력 폴더는 거부한다.
- 사용자 실행(2026-11-03): `python scripts/run_zeek.py --pcap outputs/samples/monday-head-400k.pcapng --out outputs/zeek/monday-head-400k/run-05`
  - 로그 21종, conn 8,758행.
  - `conn.log` SHA-256 `f3278aa3…`는 손으로 실행한 run-03·04와 같다.
  - manifest의 입력 해시 `67ac86ef…`는 샘플 해시와 같다.
  - 실행 시간은 약 3.7초.
- `run-01`~`run-04`는 재현 비교의 근거로 남긴다. 이후 실행은 이 스크립트로 한다.

### 검증 우선순위 조정

[DD-003](design-decisions/DD-003-verification-priority.md)에 따라 다음을 조정했다.
- 600k 샘플로 EOF를 판정하는 실험은 하지 않는다. `eof_candidate` 표시는 단계 2의 Silver 정제에서 구현한다.
- 실시간 대조는 단계 6으로 옮긴다.
- `-C` 비교는 단계 3에서 한다.

## 두 번째 작업: 5일 전체 Zeek 처리

`scripts/run_zeek.py`로 원본 PCAP 5개를 처리했다(사용자 실행, 2026-11-03).
- 원본의 입력 해시는 다시 계산하지 않았다. 입력 manifest에 크기가 일치하는 검증된 값이 있으면 그 값을 쓰고, `sha256_source`에 출처를 남긴다.
- 출력 위치: `outputs/zeek/<요일>/run-01/`.

| 요일 | conn 행 | 처리 시간(UTC) | 출력 크기 |
| --- | --- | --- | --- |
| 월 | 375,432 | 09:03:14~09:05:08 | 479M |
| 화 | 323,342 | 09:05:08~09:06:56 | 419M |
| 수 | 509,362 | 09:06:57~09:09:40 | 669M |
| 목 | 363,788 | 09:09:41~09:11:13 | 419M |
| 금 | 547,353 | 09:11:14~09:13:15 | 586M |
| 합계 | 2,119,277 | 약 10분 | 약 2.5G |

- **과거 검증과의 대조:** 월요일 375,432행과 5일 합계 2,119,277행이 과거 측정과 같다. 과거와 같은 이미지·`-C` 옵션이면 seed가 달라도 기록되는 연결은 같다. `uid`와 파일 해시는 seed 때문에 다르다.
- **Zeek stderr:** 5일 모두 비어 있다.
- **로그 종류:** 하루 전체에는 샘플에 없던 `websocket.log`, `mqtt_connect.log`가 요일에 따라 나타난다. 이 프로젝트의 모델 입력은 conn뿐이라 영향은 없다.

## 작업 순서 조정 (사용자 결정, 2026-11-03)

정답 에피소드 근거 검토(V4)를 단계 2의 Silver 테이블을 만든 뒤에 한다.
- 이유: V4는 로그를 반복해서 조회하는 작업이다. Silver 위에서 Spark SQL로 하면 조회 코드가 남고, Spark도 실제로 써 볼 수 있다.
- 설계와 충돌하지 않는다. V4는 "단계 1에서 시작, 단계 3 평가 전 동결"이다.

단계 1에서 끝낸 것:
- Zeek 실행 환경 고정: 이미지 digest, seed, 실행 manifest.
- 같은 설정의 재실행 재현(V1).
- 5일 전체 처리.

남은 것:
- V4: 단계 2 Silver 이후에 한다.
- 실시간 대조: 단계 6으로 옮겼다(DD-003).
