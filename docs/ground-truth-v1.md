# 정답 에피소드 v1 (CIC-IDS2017)

- 동결: 2026-11-05. 모델 점수를 보기 전에 정했다(설계 5.1절).
- 조건 파일: [configs/ground-truth/cic17-episodes.v1.json](../configs/ground-truth/cic17-episodes.v1.json)
- 대응표 생성: [scripts/build_ground_truth.py](../scripts/build_ground_truth.py) → `outputs/ground_truth/cic17_v1/`
  - `connections`: 에피소드에 속한 Silver 연결
  - `windows`: 그 연결이 들어간 Gold 창
- **평가 전용이다.** 이 조건은 모델·LLM 입력이나 근거 검색 필터에 쓰지 않는다.

## 만든 방법

1. **후보:** 공식 일정에서 후보를 찾는다. 공식 일정은 현지 시각이고, UTC보다 3시간 늦다.
2. **근거 확인:** Silver에서 공격자·피해자·포트·시각별 연결을 5분 단위로 본다.
3. **대조:** 개선 라벨(`CICIDS2017_improved`)의 공격 flow 시각·주소와 맞춘다. 개선 라벨의 시각은 UTC다.
4. **조건 작성:** 연결을 고르는 조건을 적는다.
   - 조건 항목: 캡처, 출발·도착 주소, 포트, 프로토콜, 연결 시작 시각(`ts`) 범위.
   - 범위는 관측된 시작·끝에 몇 분 여유를 둔다.
   - 같은 피해자·포트에서 도구가 바뀌는 경우(DoS 4종, 웹 공격 3종)는 개선 라벨 시각 사이의 빈 구간에서 자른다.
5. **상태:** 근거가 부족하면 `uncertain`으로 두고, 추가 조사가 바꿀 결론을 적는다.

## 결과 (Claude, 2026-11-05)

confirmed 16, uncertain 1.

| ID | 시나리오 | 상태 | 연결 | 창 | 자산·역할 | 개선 라벨 flow |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| 001 | FTP-Patator | confirmed | 3,992 | 14 | 1 | 3,982 |
| 002 | SSH-Patator | confirmed | 2,979 | 16 | 1 | 2,988 |
| 003 | DoS Slowloris | confirmed | 3,902 | 7 | 1 | 5,705 |
| 004 | DoS Slowhttptest | confirmed | 16,062 | 6 | 1 | 5,107 |
| 005 | DoS Hulk | confirmed | 163,454 | 6 | 1 | 159,047 |
| 006 | DoS GoldenEye | confirmed | 7,739 | 4 | 1 | 7,647 |
| 007 | Heartbleed | confirmed | 8 | 4 | 1 | 11 |
| 008 | Web Brute Force | confirmed | 1,367 | 10 | 1 | 1,365 |
| 009 | Web XSS | confirmed | 673 | 5 | 1 | 673 |
| 010 | Web SQL Injection | confirmed | 18 | 2 | 1 | 17 |
| 011 | Infiltration 외부 포트 스캔(.51) | confirmed | 1,040 | 2 | 2 | 955 |
| 012 | Infiltration Vista(.8) | confirmed | 74,160 | 114 | 12 | 70,860 |
| 013 | Infiltration MAC(.25) | confirmed | 27 | 3 | 1 | 30 |
| 014 | Infiltration .9 시도 | **uncertain** | 3 | 2 | 1 | 3 |
| 015 | Botnet ARES | confirmed | 4,964 | 408 | 5 | 4,803 |
| 016 | PortScan | confirmed | 161,210 | 19 | 2 | 159,066 |
| 017 | DDoS LOIT | confirmed | 95,683 | 5 | 1 | 95,144 |

- **두 가지 확인을 통과했다.**
  - 한 연결이 두 에피소드에 들어간 경우가 없다.
  - 모든 에피소드에 연결이 있다.
- **연결 수와 개선 라벨 flow 수는 대체로 비슷하다.** 두 도구가 "연결 하나"를 다르게 자르므로 정확히 같지 않다.
  - 개선 라벨은 CICFlowMeter의 flow다. 우리는 Zeek conn이다.
  - Slow 계열에서 차이가 큰 이유는 같은 연결을 나누는 방식이 다르기 때문이다.
- **캡처 끝 창에 걸린 에피소드가 있다.** 002(1개 창), 013(1개 창), 015(5개 창)다. 이 창은 주 비교에서 빠진다(설계 4.3절).

## 출처 사이의 불일치

- **011 외부 포트 스캔:** 공식 일정에 없다. 개선 라벨에는 `Infiltration - Portscan`으로 있다. conn에서도 998개 포트에 거절이 몰린 뚜렷한 스캔이다.
- **012 Vista 내부 스캔:** 원본 CSV는 BENIGN으로 표시한다(라벨 오류). 개선 라벨과 conn 근거는 스캔이다.
- **015 Botnet:** 공식 일정은 11:02 현지에 끝난다. conn에서는 C2가 거절한 뒤에도 봇이 17시까지 반복 연결한다. 개선 라벨은 이 구간을 `Botnet - Attempted`로 둔다. 감염된 봇의 행동이므로 포함했다.
- **002 SSH-Patator:** 첫 연결이 일정(14:00)보다 늦은 14:09다.

## conn으로 보이는 것과 보이지 않는 것

- **외부 공격자는 자산이 아니다.** NAT 주소 172.16.0.1로 보이므로 대부분은 피해 서버의 responder 관측만 생긴다.
  - 내부 자산이 출발하는 관측은 다음뿐이다: Infiltration(.8, .25, .9), Botnet(봇 5대), 방향이 뒤집혀 기록된 스캔 응답(OTH).
- **웹 공격 3종과 DoS 4종은 conn만으로 종류를 구분할 수 없다.** 같은 피해자·같은 포트다. 요청 내용은 http.log 영역이다.
- **Heartbleed는 긴 연결 하나다.** 15:12에 시작해 15:32에 기록됐다(응답 80MB). 기록 창이 시작보다 20분 늦다.
- **012에서 .3은 뺐다.** .3은 DNS·도메인 서버라 평소 통신과 섞인다(검증 범위 제한). .50은 평소 연결이 일부 섞인다.
- **015에서 뺀 것:** 172.16.0.1이 봇에게 보낸 ICMP는 방화벽 응답으로 보고 뺐다.

## 정하지 않은 것

- **성공 여부:** 012(내부 스캔이 감염 후 행동)와 015(C2 http 성공)만 `succeeded`다. 나머지는 `unknown`이다. 공격 성공 증명은 요구 사항이 아니다(설계 5.1절).
- **014:** RSTO 3개뿐이다. PCAP 내용을 보면 감염 시도 여부가 바뀔 수 있다.
