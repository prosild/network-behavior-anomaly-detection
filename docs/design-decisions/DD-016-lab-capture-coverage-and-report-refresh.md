# DD-016. 실습망 수집은 시계 경계마다 파일을 넘기고, 늘어난 사건은 보고서를 다시 만든다

- 결정일: 2026-11-18
- 요청·결정: 사용자(Claude 추천대로). 문제는 배포 VM 첫 동작 확인에서 Claude가 찾았다.
- 관련: [DD-012](DD-012-file-triggered-pipeline.md), [DD-015](DD-015-vmware-lab-deployment.md), [설계 질문 기록](../design-discussion-log.md) Q55·Q56, [단계 6 진행 기록](../stage-6-progress.md) 열셋째·열넷째 작업

## 배경(2026-11-18 VM 시험)
Kali에서 09:49(UTC)에 `ping`·`nmap -sT -p 1-100`을 실행했다. 그 뒤로 실습망에 트래픽이 없었다.
1. **마지막 활동이 채점되지 않았다.**
   - tcpdump `-G`는 시간이 지난 뒤 다음 패킷이 와야 파일을 바꾼다. nmap 파일이 열린 채 남았다.
   - 파일이 넘어간 뒤에도 nmap 창(09:45\~09:50)은 `capture_edge`였다. 캡처 경계를 마지막 패킷 시각(09:49:49)으로 잡아 "09:50까지 관측했는지 모른다"고 봤기 때문이다.
   - Claude가 배포 VM에서 ping을 보내 다음 파일을 만든 뒤에야 사건에 붙었다.
2. **사건이 늘어나도 보고서를 다시 쓰지 않았다.**
   - 사건 ID는 `캡처|자산|역할|시작 epoch`다. 09:40 창(연결 2개)으로 보고서를 만든 뒤 nmap 창이 더해져 연결이 103개가 됐지만, ID가 같아 에이전트가 건너뛰었다. 보고서는 nmap을 설명하지 않는다.

## 결정
1. **시간 기준 회전**([scripts/capture_rotate.sh](../../scripts/capture_rotate.sh)): 시계의 `ROTATE_SECONDS` 경계(5분)마다 tcpdump를 멈추고 다시 시작한다. 패킷이 없어도 넘어간다.
   - 파일 이름에 덮은 시간을 넣는다: `lab-<시작>-<끝>.pcap`(UTC, 예: `lab-20261118T094500Z-20261118T095000Z.pcap`).
   - 패킷이 없는 파일은 버린다.
   - `--immediate-mode -U`: 멈출 때 커널·출력 버퍼에 남은 패킷을 잃지 않게 한다(없을 때 시험에서 6개 중 2개를 잃음).
2. **캡처 경계의 끝 = 마지막 패킷 시각과 관측을 마친 시각 중 늦은 쪽**([zeek_ad/live_capture.py](../../zeek_ad/live_capture.py) `observed_until`).
   - 수신 처리가 이름의 덮은 시간을 `ingest_file.covered_from·covered_to`에 남긴다([013_ingest_coverage.sql](../../db/migrations/013_ingest_coverage.sql)). 패킷이 그 시간 안에 있을 때만 믿는다(1초 여유).
   - 시작 쪽(`packet_time_min`)은 그대로 첫 패킷 시각이다. Transformer가 이 값으로 창 위치를 맞추므로 바꾸지 않는다.
   - 이름에 덮은 시간이 없는 파일(손으로 넣은 시험 PCAP, 예전 수집 파일)은 예전 규칙 그대로다.
3. **늘어난 사건은 보고서를 다시 만든다**([zeek_ad/agent_store.py](../../zeek_ad/agent_store.py) `incidents_to_report`, [scripts/live_agent.py](../../scripts/live_agent.py)).
   - 보고서가 본 창 목록은 따로 저장하지 않는다. 보고서는 (작업, 사건) 키라 그 작업의 `incident_window`가 곧 보고서가 본 창이다.
   - 새 작업에서 사건마다 "가장 최근 보고서를 만든 작업의 창 목록"과 "이 작업의 창 목록"을 비교한다. 다르면 이 작업에서 보고서·판단을 다시 만들고(`changed`), 같으면 건너뛴다. 보고서가 없으면 새로 만든다(`new`).
   - 사건의 시작 창이 바뀌면 사건 ID가 달라져 새 사건이 된다(예전 ID의 보고서는 그 작업에 남는다).
4. **Slack에는 다시 보내지 않는다**(Q55). 이미 알린 사건은 대시보드가 최신 보고서를 보여 준다. 단, 아직 한 번도 보내지 않은 사건이 늘어나 보낼 대상이 되면 그때 처음 알린다.
   - [zeek_ad/slack.py](../../zeek_ad/slack.py) `alerted_before`: 같은 사건 ID의 사건 알림이 **다른 작업**에 기록돼 있으면 참. 상태 변경 알림(`status:*`)은 따지지 않는다.
   - LangGraph `early_alert`·`deliver`와 일반 함수 버전이 이 값이 참이면 Slack 기록을 건너뛴다(trace에 `slack_skipped=alerted_before`). 같은 실행 안의 두 번째 알림(템플릿 다음 LLM 보고서)은 그대로다.

## 알아야 할 한계
- 회전할 때 앞 tcpdump를 멈추고 다음 tcpdump가 듣기까지 틈이 있다(VM 실측 0.1\~0.4초, 5분마다 한 번). 그 사이 패킷은 놓친다. 겹치게 돌리면 같은 패킷이 두 파일에 들어가 연결을 두 번 세므로 겹치지 않는다.
- 덮은 시간은 수집기가 돌던 시간이지 카드가 연결되어 있던 시간을 보장하지 않는다(VMware에서 카드 연결을 끊어도 tcpdump는 돈다).
- 수집기가 꺼져 있던 시간(틈)은 경계에 드러나지 않는다. 하루의 처음과 끝만 본다(예전과 같음).
- 다시 만든 보고서의 작업에는 Slack 기록이 없다. 판단(`would_send`)은 새 작업에 있지만 알림은 처음 알린 작업에 있다. 대시보드가 `zeekad_report_job_id`로 Slack 기록을 조인하면 "보냄 판단인데 기록 없음"으로 보일 수 있다. Slack 기록은 사건 ID로 찾아야 한다.
- 다시 처리할 때 판단 모델이 `analyst_review`를 고르면 새 작업에 검토 요청이 하나 더 생긴다. 사건이 달라졌으니 다시 보게 하는 것이다. 이미 종료한 사건의 상태는 되돌리지 않는다(`apply_status`는 앞으로만 간다).
- 창은 같고 창 안의 연결만 늘어난 경우는 다시 만들지 않는다. 창은 관측이 끝난 뒤에만 채점되므로(`capture_edge` 제외) 보통 생기지 않는다.
