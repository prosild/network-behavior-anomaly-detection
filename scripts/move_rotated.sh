#!/bin/sh
# tcpdump의 파일 회전 뒤 처리 명령(-z)으로 쓴다(DD-012). $1 = 방금 다 쓴 PCAP.
# 수신 폴더와 같은 파일 시스템이면 mv는 원자적이다. 감시 프로그램은 다 쓴 파일만 보게 된다.
# INBOX는 수신 폴더의 절대 경로로 바꿔 쓴다(다른 PC에서 캡처하면 공유 폴더 경로).
INBOX="${INBOX:-/path/to/zeek_AD/data/live/inbox}"   # 컨테이너(scripts/capture_lab.sh)는 환경 변수로 준다
mv "$1" "$INBOX/"
