#!/bin/bash
# SSH 무차별 대입 생성기 — 네트워크 이상탐지 검증용(격리 실습망 전용, DD-020).
#
# 공격자가 타깃 SSH(22)에 로그인을 빠르게 반복 시도한다. 시끄러운 자격증명 공격(TA0006).
# 실제 비밀번호 사전 대입(hydra 등) 대신 BatchMode로 연결·인증 시도만 반복한다 —
# 네트워크 서명(짧은 22 연결 다수)은 같고, 비밀번호 목록이 필요 없다.
# 스캔(한 호스트의 여러 포트)과 달리 한 호스트의 한 포트에 연결이 쏟아지는 유형이다.
#
# 실행(공격자에서): bash lab_bruteforce.sh TARGET [COUNT]
#   예: bash lab_bruteforce.sh 10.10.0.20 300
# 시각은 ~/brute-<시작 UTC>.log에 남는다.
set -uo pipefail

TARGET=${1:?타깃 주소}
COUNT=${2:-300}

LOG=~/brute-$(date -u +%Y%m%dT%H%M%SZ).log
mark() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

mark "brute start -> ${TARGET}:22 count=${COUNT}"
for ((i=1; i<=COUNT; i++)); do
    timeout 3 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=2 \
        "user${i}@${TARGET}" true 2>/dev/null || true
    [ $((i % 50)) -eq 0 ] && mark "attempts=$i"
done
mark "brute end attempts=${COUNT}"
echo "----- log: $LOG"
