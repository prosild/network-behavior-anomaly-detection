#!/bin/bash
# 타깃 정상 배경 생성기 — 네트워크 이상탐지 검증용(격리 실습망 전용, DD-020).
#
# 타깃(정상 내부 호스트)이 평소처럼 여러 서버에 웹 요청을 낸다. 비커닝과 대비되는
# originator 기준을 만든다: 비커닝이 "한 상대·한 포트·규칙적 간격"이라면, 정상은
# "여러 목적지·여러 포트·불규칙한 간격(가끔 몰아서)"이다. 같은 비커닝을 이 배경 위에서
# 다시 돌리면, 점수가 평평한지(새 노드라 일괄로 꼽힘) 아니면 비커닝 창에서 달라지는지
# 대조할 수 있다.
#
# 외부 도구 없이 bash 내장 /dev/tcp만 쓴다. 목적지는 HTTP 서버로 가정한다.
#
# 목적지 파일(기본 ~/normal_endpoints.txt): 한 줄에 "host port". 예(Kali에 별칭 IP 10.10.0.60을
#   주고 benign 웹 서버로 두면 C2 10.10.0.50과 IP 그룹이 갈린다):
#     10.10.0.60 80
#     10.10.0.60 8080
#
# 실행(타깃에서):
#   bash lab_normal_client.sh 900                 기본 목적지 파일로 15분
#   bash lab_normal_client.sh 900 my_endpoints.txt
#
# 시각 기록은 ~/normal-<시작 UTC>.log에 남는다.
set -uo pipefail

DURATION=${1:-900}                               # 총 지속(초)
ENDPOINTS=${2:-~/normal_endpoints.txt}
ENDPOINTS=${ENDPOINTS/#\~/$HOME}

if [ ! -s "$ENDPOINTS" ]; then
    echo "목적지 파일이 없다: $ENDPOINTS" >&2
    echo "한 줄에 'host port' 형식으로 benign HTTP 서버를 적는다. 예:" >&2
    echo "  10.10.0.60 80" >&2
    exit 1
fi
mapfile -t EPS < <(grep -vE '^\s*(#|$)' "$ENDPOINTS")
[ ${#EPS[@]} -gt 0 ] || { echo "목적지가 비어 있다: $ENDPOINTS" >&2; exit 1; }

PATHS=(/ /index.html /status /api/health /docs /about /favicon.ico /assets/app.js)
LOG=~/normal-$(date -u +%Y%m%dT%H%M%SZ).log
END=$(( $(date +%s) + DURATION ))

mark() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

# HTTP GET 하나: 연결을 열어 요청을 보내고 응답을 잠깐 읽고 닫는다.
http_get() {
    local host=$1 port=$2 path=$3
    exec 3<>/dev/tcp/"$host"/"$port" 2>/dev/null || return 1
    printf 'GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: lab-normal\r\nConnection: close\r\n\r\n' \
        "$path" "$host" >&3 2>/dev/null
    timeout 3 cat <&3 >/dev/null 2>&1
    exec 3<&- 3>&- 2>/dev/null
    return 0
}

rand() { awk -v a="$1" -v b="$2" 'BEGIN{srand();print a+(b-a)*rand()}'; }   # [a,b) 실수
pick() { local -n arr=$1; echo "${arr[RANDOM % ${#arr[@]}]}"; }

mark "normal start, endpoints=${#EPS[@]} dur=${DURATION}s"
req=0
while [ "$(date +%s)" -lt "$END" ]; do
    # 한 번 요청하거나, 20% 확률로 2~4번 몰아서(사람이 페이지 여러 개 여는 것처럼)
    burst=1
    [ "$(awk 'BEGIN{srand();print (rand()<0.2)?1:0}')" = 1 ] && burst=$(( (RANDOM % 3) + 2 ))
    for ((b=0; b<burst; b++)); do
        ep=$(pick EPS); host=${ep%% *}; port=${ep##* }; p=$(pick PATHS)
        if http_get "$host" "$port" "$p"; then st=ok; else st=miss; fi
        req=$((req+1))
        mark "req=$req $host:$port $p $st"
        [ $b -lt $((burst-1)) ] && sleep "$(rand 0.3 1.5)"
    done
    # 요청 사이 불규칙한 생각 시간(3~20초)
    sleep "$(rand 3 20)"
done
mark "normal end req=$req"
echo "----- log: $LOG"
