# DD-015. 배포를 VMware 실습망으로 바꾼다: 배포 VM 하나 + Kali VM(격리 네트워크). DD-013을 대체한다

- 결정일: 2026-11-17
- 요청·결정: 사용자. 평가와 구성은 Claude가 제안했다.
- 관련: [DD-013](DD-013-nas-pc-deployment.md)(대체됨), [DD-012](DD-012-file-triggered-pipeline.md), [설계 질문 기록](../design-discussion-log.md) Q54

## 배경
- DD-013은 NAS(DS920+)에 처리·서비스를 두고, PC GPU worker가 딥러닝 추론을 가져가는 구조였다.
- 측정해 보니 추론은 이미 CPU로 돈다(TGN은 재현성 때문에 CPU 전용). 세 모델 채점 시간은 CIC 하루(약 1,700창) 15~24초, 실습망 하루 4~5초다(Ryzen 5700X). GPU worker는 속도 이득이 거의 없고 대기열·NFS·캡처 필터만 늘린다.
- NAS에는 사용자의 실제 데이터가 있어 Kali 공격(무차별 대입, DoS 등)의 대상으로 두기 위험하다.

## 결정
1. 이 PC의 VMware에 **배포 VM 하나**(예: Ubuntu Server 24.04)를 두고 모든 구성 요소를 Docker Compose로 올린다: tcpdump 수집, 감시 프로그램(Zeek·다시 계산·채점·에이전트), PostgreSQL(+pgvector), MLflow, 근거 API, Java 대시보드(Nginx·WAF 포함).
2. **Kali VM**은 실습용 host-only 네트워크에만 연결한다. 공격 트래픽이 집 LAN·NAS로 나가지 않는다.
3. 배포 VM의 네트워크 카드는 둘이다.
   - 관리용(NAT): 인터넷(Gemini API·패키지), Windows에서 대시보드·MLflow 접속.
   - 실습용(host-only): Kali와 연결. **tcpdump는 이 카드만 캡처한다.** 그래서 DB·Gemini 같은 파이프라인 자기 트래픽은 처음부터 섞이지 않는다(DD-013의 캡처 필터가 필요 없다).
4. 채점은 모두 CPU로 배포 VM 안에서 한다. GPU worker와 DB 작업 대기열(DD-013 결정 3·4)은 만들지 않는다.
5. 처음에는 배포 VM 자신을 공격 대상으로 둔다. 피해 VM을 더하고 실습망 트래픽을 엿보게(promiscuous) 하는 것은 이후 확장이다.

## 알아야 할 한계
- PC가 켜져 있을 때만 동작한다(상시 수집이 아니다). 포트폴리오 시연에는 충분하다.
- 배포 VM은 자기 카드로 오가는 트래픽과 브로드캐스트만 본다.
- VMware는 WSL2와 함께 쓸 때 Windows 하이퍼바이저 위에서 돌아 조금 느릴 수 있다.
- 모델은 CIC 월요일로 학습했다. 실습망 점수는 그 기준과의 차이로 읽는다(재학습하지 않음, Q44).

## 배포 전에 할 일
- ~~실습망 대역을 `configs/assets.lab.v1.json`에 넣는다.~~ 실습망 대역은 시험 PCAP과 같은 `10.10.0.0/24`로 정했다(2026-11-18). 설정을 고치지 않는다. 배포 VM 10.10.0.10, Kali 10.10.0.50, VMnet2(host-only, Windows 연결 없음, DHCP 없음). 만드는 순서: [vm-deployment.md](../vm-deployment.md).
- 배포 VM 사양: CPU 4, 메모리 8GB, 디스크 60GB. 근거: CPU 4개로 제한한 다시 계산이 167초, 최고 메모리 1.97GB(2026-11-18 실측).
- ~~다시 계산 결과(리비전, 하나에 약 86MB)를 최신 몇 개만 남기는 정리 기능.~~ 만들었다(2026-11-19): 그날 성공 리비전 최신 2개와 그보다 새로운 것만 남긴다. [단계 6 진행 기록](../stage-6-progress.md) 스물한째 작업.
- 같은 캡처에 채점 작업이 여러 개 생기는 실습망 특성을 대시보드 계약에 반영한다(Q54).
