#!/bin/sh
# 실습망 수집(DD-015, DD-016). Compose의 collector 서비스가 root로 시작하지만, 곧바로 일반 계정(zeekad, uid 1000)이 된다.
# 컨테이너가 받는 권한은 NET_RAW(캡처)와 SETUID·SETGID(계정 바꾸기)뿐이다.
# 1. zeekad로 spool·inbox 폴더를 만들고, 지난번 실행이 남긴 파일(멈출 때 쓰던 마지막 파일)을 수신 폴더로 옮긴다.
#    멈춘 뒤라 더 쓰이지 않는 파일이다. 이름에 덮은 시간의 끝이 없어 패킷 시각만으로 경계를 잡는다.
# 2. 회전 반복(scripts/capture_rotate.sh)도 zeekad로 실행하고 NET_RAW 하나만 넘긴다(ambient capability).
#    그래서 tcpdump가 쓰는 파일의 주인이 처음부터 uid 1000이다.
#    tcpdump -Z를 쓰지 않는 이유: Debian tcpdump는 첫 파일을 root로 연 뒤 주인을 바꾼다. 그러려면 root에게
#    DAC_OVERRIDE·CHOWN(모든 파일 권한 무시·주인 변경)을 줘야 한다(2026-11-18 시험).
# 환경 변수: LAB_IFACE(실습망 카드 이름, 필수), ROTATE_SECONDS(기본 300), LIVE_DIR(기본 /app/data/live)
set -eu
export LIVE_DIR="${LIVE_DIR:-/app/data/live}"
export ROTATE_SECONDS="${ROTATE_SECONDS:-300}"
if [ -z "${LAB_IFACE:-}" ]; then
    echo "LAB_IFACE(실습망 카드 이름, 예: ens37)를 deploy/.env에 적는다" >&2
    exit 1
fi
export LAB_IFACE
setpriv --reuid=zeekad --regid=zeekad --init-groups sh -c '
    mkdir -p "$1/spool" "$1/inbox"
    for f in "$1"/spool/*.pcap; do
        [ -e "$f" ] && mv "$f" "$1/inbox/" && echo "지난 실행의 파일을 수신 폴더로: $(basename "$f")"
    done
    true' sh "$LIVE_DIR"
echo "캡처 시작: $LAB_IFACE, ${ROTATE_SECONDS}초 경계마다 파일 회전(패킷이 없어도) → $LIVE_DIR/inbox"
exec setpriv --reuid=zeekad --regid=zeekad --init-groups --inh-caps=-all,+net_raw --ambient-caps=-all,+net_raw \
     sh /app/scripts/capture_rotate.sh
