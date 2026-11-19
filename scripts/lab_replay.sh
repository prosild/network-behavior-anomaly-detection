#!/bin/sh
# 실습망 배경 트래픽 재생(DD-017). 배포 VM에서 일회용 컨테이너(zeekad-replay)로 실행한다.
# 실습용 카드로 PCAP을 원래 시간 간격(1배속) 그대로 보낸다. 수집기(tcpdump)는 그 카드에서 나가는 패킷도 캡처한다.
# 큰 프레임(CIC의 합쳐진 TCP 조각, 최대 8,754바이트)을 그대로 보내려고 재생 동안만 카드 MTU를 올리고, 끝나면 되돌린다.
# MTU를 바꾸면 카드가 잠깐 다시 붙을 수 있어 시작 시각 전에(트래픽이 없을 때) 바꾼다.
# 인자: PCAP 경로, 시작 시각(오늘 UTC HH:MM, 5분 경계, 생략하면 바로). 환경 변수: LAB_IFACE(필수), REPLAY_MTU(기본 9000)
# 예(배포 VM, ~/zeek_AD):
#   docker build -t zeekad-replay:dev -f deploy/replay.Dockerfile .
#   docker run -d --name zeekad-replay --network host --cap-add NET_RAW --cap-add NET_ADMIN -e LAB_IFACE=ens34 \
#       -v "$PWD/outputs/lab_background/v1:/bg:ro" zeekad-replay:dev /bg/background.pcap 04:20
#   docker logs -f zeekad-replay
set -eu
PCAP="$1"
AT="${2:-}"
: "${LAB_IFACE:?LAB_IFACE(실습망 카드 이름)가 필요하다}"
REPLAY_MTU="${REPLAY_MTU:-9000}"
log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

OLD_MTU=$(cat "/sys/class/net/$LAB_IFACE/mtu")
restore() { ip link set dev "$LAB_IFACE" mtu "$OLD_MTU" && log "MTU 되돌림: $OLD_MTU"; }
trap restore EXIT
trap 'exit 130' INT TERM

if [ -n "$AT" ]; then
    START=$(date -u -d "$(date -u +%F) $AT:00" +%s)
    NOW=$(date -u +%s)
    if [ $((START % 300)) -ne 0 ] || [ $((START - NOW)) -lt 60 ]; then
        log "시작 시각은 60초 이상 뒤의 5분 경계여야 한다: $AT" >&2
        exit 1
    fi
fi
ip link set dev "$LAB_IFACE" mtu "$REPLAY_MTU"
log "MTU $OLD_MTU → $REPLAY_MTU ($LAB_IFACE)"
if [ -n "$AT" ]; then
    log "시작 대기: $AT UTC"
    sleep $((START - $(date -u +%s)))
fi
log "재생 시작: $PCAP"
tcpreplay --intf1="$LAB_IFACE" --stats=300 "$PCAP"
log "재생 끝"
