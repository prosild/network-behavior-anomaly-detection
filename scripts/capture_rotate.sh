#!/bin/sh
# 시간 기준 파일 회전(DD-016). scripts/capture_lab.sh가 zeekad 계정·NET_RAW 권한으로 실행한다.
#
# 왜: tcpdump -G는 시간이 지난 뒤 "다음 패킷이 와야" 파일을 바꾼다. 조용한 실습망에서는 공격이 끝난 뒤
#     트래픽이 없어 마지막 파일이 열린 채 남고, 그 공격은 채점되지 않았다(2026-11-18 nmap 시험).
# 어떻게:
# 1. 시계의 ROTATE_SECONDS 경계(예: 5분이면 :00, :05, ...)까지만 tcpdump를 돌리고 멈춘다. 패킷이 없어도 멈춘다.
#    경계에 맞추면 파일 하나가 채점 창(5분) 하나와 겹친다.
# 2. 다 쓴 파일은 덮은 시간을 이름에 넣어 수신 폴더로 옮긴다: lab-<시작>-<끝>.pcap(UTC, 예: 20261118T094500Z).
#    수신 처리(zeek_ad.ingest)가 이 끝 시각을 읽어 "이 시각까지 관측했다"는 캡처 경계로 쓴다.
#    끝 시각은 tcpdump를 멈추기 직전에 잰다(초 아래 버림). 그래서 tcpdump는 그 시각까지 확실히 돌았다.
# 3. 패킷이 하나도 없는 파일(pcap 머리 24바이트뿐)은 버린다. 처리할 내용이 없고, 내용이 늘 같아 중복으로만 쌓인다.
# 4. 앞 tcpdump를 멈추고 다음 tcpdump가 듣기 시작하기까지 틈이 있다(VM 실측 0.1~0.4초). 그 사이의 패킷은 놓친다
#    (알려진 한계, 5분마다 한 번). 겹치게 돌리면 같은 패킷이 두 파일에 들어가 Zeek가 연결을 두 번 센다.
#    그래서 다음 파일은 경계보다 조금 늦게 시작하고, 이름의 시작 시각은 초 아래를 버린 값이다.
# 5. 컨테이너를 멈추면(SIGTERM) 쓰던 파일을 마무리해 넘기고 끝낸다.
set -u
SPOOL="$LIVE_DIR/spool"
INBOX="$LIVE_DIR/inbox"
ERR="$SPOOL/.tcpdump.err"

stamp() { date -u -d "@$1" +%Y%m%dT%H%M%SZ; }

stopping=0
trap 'stopping=1' TERM INT

while [ "$stopping" = 0 ]; do
    start=$(date -u +%s)
    secs=$((ROTATE_SECONDS - start % ROTATE_SECONDS))
    [ "$secs" -le 2 ] && secs=$((secs + ROTATE_SECONDS))   # 경계 직전이면 다음 경계까지(아래 2초 확인보다 짧지 않게)
    part="$SPOOL/lab-$(stamp "$start").pcap"
    # 필터를 두지 않는다: 이 카드에는 실습망 트래픽만 지난다(관리·DB·Gemini 트래픽은 다른 카드다).
    # --immediate-mode: 커널이 패킷을 모아 두지 않고 바로 넘긴다. -U: 패킷마다 파일에 쓴다.
    # 둘이 없으면 멈출 때 아직 넘겨받지 못한 패킷(최대 약 1초 분량)을 잃는다(2026-11-18 시험: 받은 6개 중 4개만 저장).
    tcpdump -i "$LAB_IFACE" -n --immediate-mode -U -w "$part" 2> "$ERR" &
    pid=$!
    sleep 2
    if ! kill -0 "$pid" 2>/dev/null; then
        # 곧바로 끝났다(카드 이름 오류, 권한 등). 컨테이너를 끝내 Docker가 다시 시작하게 한다.
        echo "tcpdump를 시작하지 못했다:" >&2
        cat "$ERR" >&2
        exit 1
    fi
    sleep $((secs - 2)) &
    spid=$!
    wait "$spid" || true          # SIGTERM이 오면 trap이 돌고 wait가 바로 끝난다
    kill "$spid" 2>/dev/null || true
    end=$(date -u +%s)
    if ! kill -0 "$pid" 2>/dev/null; then
        # 경계 전에 tcpdump가 스스로 끝났다(카드가 사라짐 등). 덮은 시간을 믿을 수 없어 넘기지 않고 끝낸다.
        # 파일은 spool에 남고, 다시 시작할 때 capture_lab.sh가 끝 시각 없는 이름 그대로 넘긴다(패킷 시각으로 경계).
        echo "tcpdump가 일찍 끝났다:" >&2
        cat "$ERR" >&2
        exit 1
    fi
    # 비대화형 셸의 배경 작업은 SIGINT를 무시하므로 SIGTERM으로 멈춘다(tcpdump는 버퍼를 비우고 파일을 닫는다).
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" || true
    size=$(stat -c %s "$part" 2>/dev/null || echo 0)
    if [ "$size" -le 24 ]; then
        rm -f "$part"
        continue
    fi
    name="lab-$(stamp "$start")-$(stamp "$end").pcap"
    mv "$part" "$INBOX/$name"
    echo "넘김: $name (${size}바이트)"
done
echo "수집 멈춤"
