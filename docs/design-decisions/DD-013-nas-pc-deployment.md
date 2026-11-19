# DD-013. 배포 구조: 시놀로지 NAS(수집·처리·서비스) + PC GPU worker(딥러닝 추론, pull)

- 결정일: 2026-11-17
- **상태: [DD-015](DD-015-vmware-lab-deployment.md)로 대체됨(2026-11-17).** 기록으로 남긴다.
- 요청·결정: 사용자. 구성과 작업 전달 방식은 Claude가 제안했고 사용자가 골랐다.
- 관련: [설계 질문 기록](../design-discussion-log.md) Q44, [DD-012](DD-012-file-triggered-pipeline.md), 설계 7절·단계 7

## 배경
- 목적은 모델 성능이 아니다. 실제 트래픽을 받아 이상을 탐지하는 완성된 파이프라인을 보이는 것이다(Q44).
- 사용자 환경
  - NAS: 시놀로지 DS920+(Intel Celeron J4125, x86-64, 4코어), 메모리 20GB, Container Manager(Docker).
  - PC: RTX 3080 12GB, WSL2. NAS와 같은 LAN에 있다.
  - 공격 트래픽: 사용자 PC의 Kali Linux에서 NAS 쪽으로 보낸다.

## 결정
1. **수집도 NAS가 한다.** NAS의 tcpdump 컨테이너(host 네트워크, NET_RAW·NET_ADMIN 권한)가 NAS 인터페이스를 캡처한다. 5분마다 파일을 닫고(`-G 300`) 수신 폴더로 옮긴다(DD-012의 파일 계약).
2. **NAS(Docker Compose)에 두는 것**: 수집, 감시 프로그램, Zeek, 전처리(Silver·Gold·이벤트·그래프 입력, Spark local), CPU 모델(꼬리 희귀도), 결합 큐, 근거, PostgreSQL(+pgvector), MLflow, 근거 API, LangGraph(보고서·전송 판단, Gemini 호출), Slack, Java 대시보드.
3. **PC에 두는 것**: GPU worker 하나. 딥러닝 모델(Transformer, TGN) 추론만 한다.
4. **작업 전달은 pull이다.** NAS가 "딥러닝 채점 필요" 작업을 DB에 등록하고, PC worker가 주기적으로 가져가(행 잠금) 점수를 DB에 쓴다. PC가 꺼져 있으면 작업은 대기로 남고, 켜지면 처리한다. 점수가 모두 모이면 NAS가 결합 큐 이후를 이어서 한다.
5. PC는 NAS의 Gold·그래프 파일을 **NFS**로 마운트해 읽는다. SMB를 쓰지 않는 이유는 3절의 캡처 필터 때문이다.

## 캡처 범위와 알아야 할 한계
- NAS는 스위치에 연결되어 있으므로 **NAS가 주고받는 트래픽과 브로드캐스트·멀티캐스트만** 본다. LAN 전체를 보려면 포트 미러링 스위치가 필요하다. 이 구성에서 탐지 대상 자산은 사실상 NAS 자신이고, 다른 LAN 호스트는 상대(peer)로 나타난다.
- **파이프라인 자기 트래픽을 빼야 한다.** PC worker ↔ NAS의 DB(55432)·MLflow·NFS(2049) 연결도 캡처에 잡혀 다시 분석되는 되먹임이 생긴다. 캡처 필터로 "PC 주소이면서 이 포트들인 트래픽"만 뺀다. 공격에 흔한 SMB(445)·SSH(22)·HTTP(S)는 빼지 않는다.
- Kali가 PC와 **같은 IP**로 나가면(WSL2 기본 NAT, VM의 NAT 모드) 공격과 파이프라인 트래픽이 출발지 IP로 구분되지 않는다. 포트로는 구분되지만, 공격자 IP를 따로 보이려면 Kali VM을 브리지 모드로 두어 별도 LAN IP를 받게 한다(사용자 확인 필요).
- 모델은 CIC 월요일로 학습했다. 실습망 점수는 그 기준과의 차이로 읽는다(재학습하지 않음, Q44).

## 바꿔야 할 구현
- 모델 묶음 채점을 CPU 부분(NAS)과 딥러닝 부분(PC)으로 나눈다. 결합 큐는 둘이 모인 뒤 만든다.
- DB 작업 대기열: 대기·처리 중·완료·실패 상태와 잠금(`FOR UPDATE SKIP LOCKED`), 처리 중 멈춘 작업의 재시도 시간.
- 지금 PC의 PostgreSQL·MLflow를 NAS로 옮긴다. NAS용 Compose, PC worker 실행 방법.
- 단계 7의 모델 교체·롤백은 이 구조 위에서 한다(PC worker도 작업마다 고정한 묶음 버전을 쓴다).
