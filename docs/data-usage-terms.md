# CIC-IDS2017 이용·재배포 조건

- 확인일: 2026-11-03. Claude가 공식 페이지를 웹으로 조회했다.
- 범위: 데이터셋 제공처(UNB CIC)의 공개 문구만 확인했다. 법률 검토가 아니다.

## 공식 출처의 문구

| 출처 | 확인한 내용 |
| --- | --- |
| [CIC 데이터셋 목록 FAQ](https://www.unb.ca/cic/datasets/index.html) | CIC의 모든 데이터셋은 어떤 형태로든 재배포·재게시·미러링할 수 있다. 다만 데이터를 쓰거나 재배포할 때는 데이터셋과 지정 논문을 인용해야 한다. 상업적 이용도 같은 조건이다. 데이터셋별 라이선스 문구는 각 페이지의 다운로드 버튼 위에 둔다 |
| [CIC-IDS2017 페이지](https://www.unb.ca/cic/datasets/ids-2017.html)의 License 절 | 연구자에게 공개된 자료이며 아래 논문을 인용하라는 내용이다. CC·Apache 같은 이름 있는 라이선스는 표시되어 있지 않다 |

지정 인용 논문:

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.

제3자 미러(Hugging Face, Zenodo 등)에 Apache-2.0이나 CC-BY 4.0이 붙은 경우가 있다. 이는 그 사본이나 파생물에 붙인 표시이고 원본의 조건이 아니다. 원본 조건의 근거로 쓰지 않는다.

## 이 프로젝트의 적용 방침

1. **인용:** README와 결과 보고서에 데이터셋 페이지와 위 논문을 인용한다.
2. **원본은 저장소에 넣지 않는다.** PCAP·CSV와 대형 Zeek 로그는 Git에 올리지 않는다(`.gitignore`). 이유는 라이선스가 아니라 용량(약 50.78 GiB)과 재현성이다. 사용자는 공식 페이지에서 내려받게 안내한다. [입력 manifest](../manifests/cic-ids-2017.inputs.v1.json)의 경로·크기·SHA-256으로 같은 원본인지 확인할 수 있다.
3. **공개해도 되는 것:** 집계 결과표, manifest, 설정, 코드, 작은 예시 행. 위 FAQ상 재게시가 허용되고 인용 조건을 지키면 된다.
4. **패킷 내용은 외부로 보내지 않는다.** PCAP에는 전체 payload가 있다. 테스트베드에서 만든 트래픽이지만, LLM·Slack·trace로는 설계 9.1절과 [DD-001](design-decisions/DD-001-slack-delivery-jev-gate.md)의 허용 필드만 보낸다. 이것은 라이선스 조건이 아니라 이 프로젝트의 입력 경계 원칙이다.

## 남은 확인

- **개선 라벨:** 설계 3.1절의 재검토 연구(Engelen 등)의 최신 개선 데이터는 공개 다운로드할 수 있다. 2026-11-03 확인.
  - 위치: [CNS2022 페이지](https://intrusion-detection.distrinet-research.be/CNS2022/index.html), 파일 목록 `Datasets/`.
  - 파일: `CICIDS2017_improved.zip`, 328M, 2023-04-27 수정. 등록 요구는 보이지 않았다.
  - 페이지에 라이선스 문구가 없다. 쓸 때는 CIC 원본 인용에 더해 CNS 2022 논문 "Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018"을 인용한다.
  - 수정한 CICFlowMeter로 만든 flow 단위 자료로 보이지만, 내려받아 확인하기 전까지 형식을 확정하지 않는다. Zeek 연결과의 대응은 원본 CSV와 같이 통신 키·시간 후보로 한다.
  - 페이지 안내: "Attempted" flow를 별도 학습 라벨로 쓰지 말 것. 이 프로젝트는 라벨로 학습하지 않는다. 다만 설계 5.1절의 시도/성공 구분에 참고할 수 있다.
  - **확보함(2026-11-03):** 사용자가 받아 `CICIDS2017_improved/`에 요일별 CSV 5개로 풀어 두었다. 합계 1,152,270,765 bytes이고 Git에서 제외했다.
    - 파일별 크기·SHA-256은 [manifest](../manifests/cicids2017-improved.inputs.v1.json)에 기록했다. zip 해시는 남기지 못했다.
    - 목록 검사: `python3 scripts/check_inputs.py --input-root CICIDS2017_improved --manifest manifests/cicids2017-improved.inputs.v1.json`
    - 단계 1의 정답 후보 대조에서 쓴다.
- **조건 변경:** 위 내용은 확인일 기준이다. 공개 직전에 공식 페이지를 다시 확인한다.
- **시간대:** 공식 일정에는 시간대 표기가 없다. 일정 시각이 PCAP 시각과 UTC-3으로 맞는다는 것은 이전 측정 결과다. 단계 1에서 공격 후보별로 확인한다(체크리스트 V1).
