# 파일 단위 자동 파이프라인: 켜는 방법과 수집 장비 설정

- 결정: [DD-012](design-decisions/DD-012-file-triggered-pipeline.md)
- **배포 VM(DD-015)에서 돌릴 때는 [vm-deployment.md](vm-deployment.md)를 따른다.** 수집(tcpdump)·감시 프로그램·채점이 모두 Compose 서비스로 돈다. 아래 내용은 이 PC에서 손으로 돌리는 방법과 동작 원리다.
- 상태: **기본으로 꺼져 있다**(`configs/pipeline/live.v1.json`의 `"enabled": false`).
- 지금 자동으로 이어지는 단계: 수신 → 저장 → Zeek → 그날 다시 계산(Silver → Gold → 그래프 → 채점 → 근거 → DB, `scripts/live_recompute.py`) → 에이전트(`scripts/live_agent.py`). 아래 흐름도는 Zeek까지만 자세히 그린다. 다시 계산 결과는 `outputs/live/runs/<캡처 ID>/<리비전>/`에 쓰고, 성공하면 그날 오래된 리비전을 정리한다(`keep_revisions`, [단계 6 진행 기록](stage-6-progress.md) 스물한째 작업).

## 1. 전체 흐름

```
[수집 장비]  tcpdump -G 300 → 5분마다 파일을 닫음 → move_rotated.sh가 수신 폴더로 mv
                                                              │
[이 PC]     data/live/inbox/  ←── 감시 프로그램(scripts/live_watcher.py)이 poll_seconds마다 확인
              │ 1. 마지막 수정 후 min_age_seconds(10초)가 지난 파일만 집음
              │ 2. sha256 → 처리 기록(DB zeekad.ingest_file)에 있으면 중복으로 치움(received면 끊긴 처리라 이어서 함)
              │ 3. capinfos로 패킷 수·첫/마지막 패킷 시각 → 캡처 ID = lab-<첫 패킷 UTC 날짜>
              ▼ 4. data/live/store/<캡처 ID>/ 로 옮겨 보관
            Zeek(Docker, configs/zeek/run.v2.json)
              ▼ 5. outputs/live/zeek/<캡처 ID>/<파일>-<해시 8자리>/  (conn·dns·http… 로그)
            처리 기록 status: received → zeek_done (실패하면 failed + error)
            옮긴 뒤 끊겨 received로 10분(stale_received_seconds) 넘게 남은 파일은 감시 프로그램이 이어서 처리
```

## 2. 켜기 전에 준비할 것

| 준비 | 확인 방법 |
| --- | --- |
| PostgreSQL 실행 | `docker compose -f deploy/compose.yaml --env-file deploy/.env up -d` 후 `docker ps`에 `zeekad-postgres-1` |
| 표 생성 | `python scripts/db_migrate.py` (`004_ingest.sql`까지 적용) |
| Python 환경 | `conda activate zeek-ad` |
| Docker와 Zeek 이미지 | `docker image ls zeek/zeek` (없으면 첫 실행 때 받는다) |
| capinfos | `capinfos -v` (Ubuntu: `wireshark-common` 패키지) |
| 실습망 자산 설정 | 실습망 내부 대역을 담은 설정 파일. **아직 없음**, 채점 연결 때 만든다 |
| 모델 해석 | 재학습하지 않는다(Q44). 실습망 점수는 CIC 월요일 정상 트래픽과의 차이로 읽는다 |

## 3. 수집 장비 설정(실습망)

**원칙: 다 쓴 파일만 수신 폴더로 옮긴다.** 쓰는 중인 파일을 수신 폴더에 직접 쓰면 앞부분만 처리된다. 감시 프로그램의 10초 대기는 보조 장치일 뿐이다.

**어디서 캡처할지.** WSL2는 자기 가상 네트워크만 본다. VirtualBox나 VMware 안의 Kali↔피해 VM 트래픽은 WSL에서 보이지 않을 수 있다. 다음 중 하나를 쓴다.
- 피해 VM(또는 같은 가상 네트워크의 리눅스 VM) 안에서 tcpdump로 캡처하고, 공유 폴더로 이 PC의 수신 폴더에 넘긴다.
- Windows에서 Wireshark의 `dumpcap`으로 가상 네트워크 어댑터를 캡처한다. `dumpcap`은 회전 후 명령(-z)이 없다. 그래서 가장 최근 파일을 뺀 나머지를 옮기는 작은 스크립트를 따로 돌려야 한다.

**tcpdump 예(리눅스 캡처 장비):**
```bash
# move_rotated.sh 안의 INBOX를 수신 폴더(공유 폴더) 절대 경로로 바꾼다
sudo tcpdump -i <인터페이스> -G 300 -w '/capture/spool/lab-%Y%m%d-%H%M%S.pcap' \
     -z /path/to/zeek_AD/scripts/move_rotated.sh
```
- `-G 300`: 5분마다 새 파일. 지연과 파일 경계 연결 분할 사이의 균형이다. 짧을수록 빨리 보이지만 잘리는 연결이 늘어난다.
- `/capture/spool`과 수신 폴더가 같은 파일 시스템이어야 `mv`가 원자적이다. 다른 파일 시스템이면 복사 중인 파일이 보일 수 있다. 그때는 수신 폴더 안의 임시 이름(예: `.part`)으로 복사한 뒤 이름을 바꾼다. 감시 프로그램은 `*.pcap`·`*.pcapng`만 본다.
- 캡처 장비의 시계를 맞춘다(NTP). 캡처 ID와 시간 창이 패킷 시각을 쓴다.

## 4. 켜기

1. `configs/pipeline/live.v1.json`에서 `"enabled": true`로 바꾼다. 수신 폴더 경로(`inbox`)를 바꾸려면 여기서 바꾼다.
2. 다음 중 하나로 실행한다(프로젝트 루트, `conda activate zeek-ad`).
   - 계속 감시: `python scripts/live_watcher.py`
     - 30초마다 확인한다. 끄려면 Ctrl+C.
     - 터미널을 닫아도 돌게 하려면 `nohup python scripts/live_watcher.py > outputs/live/watcher.log 2>&1 &`.
   - 주기 실행: `--once`는 한 번 훑고 끝난다. cron 예: `* * * * * cd /path/to/zeek_AD && /path/to/conda/envs/zeek-ad/bin/python scripts/live_watcher.py --once >> outputs/live/watcher.log 2>&1`
3. 끄기: 프로세스를 멈추고 `enabled`를 다시 `false`로 둔다.

## 5. 확인

```bash
# 처리 기록
python - <<'EOF'
from zeek_ad.db import connect
with connect("zeekad_api") as c:
    for r in c.execute("SELECT file_name, capture_id, packets, first_packet_at, status, error, zeek_run_dir "
                       "FROM ingest_file ORDER BY first_packet_at DESC LIMIT 20"):
        print(r)
EOF
```
- `failed`면 `error` 칸을 본다. Zeek 실패는 실행 폴더의 `zeek.stderr.txt`(같은 이름 + `.tmp` 폴더)에 남는다.
- 같은 파일을 다시 처리하고 싶으면 그 행을 지우고 `data/live/store/`의 파일을 수신 폴더로 다시 옮긴다.

## 6. 시험(켜지 않고)

캡처 권한이 없어도 시험할 수 있다. 시험용 PCAP을 만들어 `--force`로 한 번 돌린다.
```bash
python tests/pcap_fixture.py /tmp/lab-a.pcap --start 2026-12-01T01:00:00Z
mv /tmp/lab-a.pcap data/live/inbox/ && touch -d "1 minute ago" data/live/inbox/lab-a.pcap
python scripts/live_watcher.py --once --force
```
