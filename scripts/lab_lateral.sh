#!/bin/bash
# 측면 이동(lateral movement) 생성기 — 네트워크 이상탐지 검증용(격리 실습망 전용, DD-020).
#
# 침해된 pivot이 여러 내부 호스트의 SMB(445)에 차례로 접속한다. "한 originator → 평소 없던
# 여러 내부 상대"라는 관계적 이상(TGN이 보려는 것)을 만든다. 스캔(한 호스트의 여러 포트)과
# 달리 여러 호스트의 한 포트로 퍼지는 fan-out이다.
#
# smbclient가 있으면 공유 목록 질의로 실제 SMB 트래픽(smb.log)을 만들고, 없으면 bash
# /dev/tcp로 445 연결만 연다. 외부 설치는 없다.
#
# 실행(pivot에서): bash lab_lateral.sh ROUNDS DELAY HOST1 HOST2 ...
#   예: bash lab_lateral.sh 10 60 10.10.0.20 10.10.0.21 10.10.0.22 10.10.0.23
#       → 4개 내부 호스트를 60초마다 한 바퀴, 10바퀴(약 10분, 2창).
# 시각은 ~/lateral-<시작 UTC>.log에 남는다(정답 시간표).
set -uo pipefail

ROUNDS=${1:?바퀴 수}; shift
DELAY=${1:?바퀴 간격 초}; shift
HOSTS=("$@")
[ ${#HOSTS[@]} -gt 0 ] || { echo "대상 호스트를 하나 이상 준다" >&2; exit 1; }

LOG=~/lateral-$(date -u +%Y%m%dT%H%M%SZ).log
mark() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

have_smbclient=0
command -v smbclient >/dev/null 2>&1 && have_smbclient=1

# 호스트 하나에 SMB 접속 시도.
touch_smb() {
    local h=$1
    if [ "$have_smbclient" = 1 ]; then
        smbclient -N -L "//$h" >/dev/null 2>&1 && return 0 || return 1
    else
        (exec 3<>/dev/tcp/"$h"/445) 2>/dev/null && { exec 3<&- 3>&- 2>/dev/null; return 0; } || return 1
    fi
}

mark "lateral start, hosts=${#HOSTS[@]} rounds=$ROUNDS delay=${DELAY}s smbclient=$have_smbclient"
for ((r=1; r<=ROUNDS; r++)); do
    hit=0
    for h in "${HOSTS[@]}"; do
        if touch_smb "$h"; then hit=$((hit+1)); fi
    done
    mark "round=$r smb_ok=$hit/${#HOSTS[@]}"
    [ "$r" -lt "$ROUNDS" ] && sleep "$DELAY"
done
mark "lateral end rounds=$ROUNDS"
echo "----- log: $LOG"
