#!/bin/bash
# 비커닝(C2 신호) 생성기 — 네트워크 이상탐지 검증용(격리 실습망 전용, DD-020).
#
# 침해된 내부 호스트에서 실행해, C2에 고정 간격(+지터)으로 짧은 연결을 반복한다.
# nmap 스캔과 달리 조용한 공격이라, 창 하나만 보는 통계 모델(꼬리 희귀도)로는 잘 안 보이고
# 자산의 창별 흐름이 바뀌는 문맥적 이상(Transformer)과 평소 없던 상대와의 연결(TGN)로
# 드러나길 기대한다. 잡히는지 자체가 아니라 "이런 행동이 수집·채점까지 흐르는가"를 본다.
#
# 역할: 타깃(10.10.0.20) = 침해 호스트(여기서 실행), Kali(10.10.0.50:PORT) = C2.
# 외부 도구 없이 bash 내장 /dev/tcp만 쓴다(타깃에 nc가 없어도 된다).
#
# C2 쪽(Kali)에서 먼저 리스너를 띄운다(반복 연결 수신):
#   ncat -lk 4444 >/dev/null
#
# 실행(타깃에서):
#   bash lab_beacon.sh 10.10.0.50 4444 60 0.2 1800
#   인자: C2주소 C2포트 평균간격초 지터비율 지속초
#   위 예: 평균 60초(±20%) 간격으로 30분. 5분 창마다 신호 약 5개.
#
# 시각 기록은 ~/beacon-<시작 UTC>.log에 남는다. 이것이 정답 시간표다(탐지 결과와 따로 둔다).
set -uo pipefail

C2_HOST=${1:?C2 주소}
C2_PORT=${2:?C2 포트}
INTERVAL=${3:-60}       # 평균 간격(초)
JITTER=${4:-0.2}        # 지터 비율(0.2 = ±20%)
DURATION=${5:-1800}     # 총 지속(초)

LOG=~/beacon-$(date -u +%Y%m%dT%H%M%SZ).log
END=$(( $(date +%s) + DURATION ))

mark() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

# 신호 하나: TCP 연결을 열어 한 줄 보내고 바로 닫는다(짧은 연결).
beacon_once() {
    exec 3<>/dev/tcp/"$C2_HOST"/"$C2_PORT" 2>/dev/null || return 1
    printf 'beacon %s %s\n' "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >&3 2>/dev/null
    exec 3<&- 3>&- 2>/dev/null
    return 0
}

mark "beacon start -> ${C2_HOST}:${C2_PORT} interval=${INTERVAL}s jitter=${JITTER} dur=${DURATION}s"
beat=0
while [ "$(date +%s)" -lt "$END" ]; do
    beat=$((beat+1))
    if beacon_once "$beat" 2>/dev/null; then st=ok; else st=miss; fi
    mark "beat=$beat $st"
    # 평균 INTERVAL, ±JITTER 범위의 다음 간격. 규칙적이되 똑같지는 않게.
    nap=$(awk -v i="$INTERVAL" -v j="$JITTER" 'BEGIN{srand(); print i*(1-j+2*j*rand())}')
    sleep "$nap"
done
mark "beacon end beats=$beat"
echo "----- log: $LOG"
