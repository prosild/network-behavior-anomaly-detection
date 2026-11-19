#!/bin/bash
# 실습망 시험 시나리오(Kali에서 실행). 활동 하나를 5분 창 하나에 넣어, 어느 활동을 어느 모델이 잡았는지 가른다.
# 대상은 실습망(VMnet2) 안의 배포 VM 하나뿐이다. 외부로 나가는 트래픽은 없다(DD-015).
# 각 활동은 5분 경계 5초 뒤에 시작한다(수집 파일 회전 틈 약 0.4초를 피한다, DD-016 한계).
# 시각 기록은 ~/scenario-<시작 UTC>.log에 남고 끝에 화면에도 출력한다. 이것이 정답 시간표다(탐지 결과와 따로 둔다).
# 실행(root 권한 필요 없음):
#   bash lab_scenario.sh          다음 5분 경계부터 바로(약 20분)
#   bash lab_scenario.sh 05:10    오늘 UTC 05:10부터(5분 경계만). 배경 트래픽과 시간을 맞출 때(DD-017)
TARGET=10.10.0.10
LOG=~/scenario-$(date -u +%Y%m%dT%H%M%SZ).log

wait_boundary() {   # 다음 5분 경계 + 5초까지 기다린다
    sleep $(( 300 - $(date -u +%s) % 300 + 5 ))
}
mark() {            # UTC 시각과 함께 기록
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"
}

if [ -n "${1:-}" ]; then
    START=$(date -u -d "$(date -u +%F) $1:00" +%s) || exit 1
    NOW=$(date -u +%s)
    if [ $(( START % 300 )) -ne 0 ] || [ $(( START - NOW )) -lt 20 ]; then
        echo "start must be a future 5-min boundary (UTC), at least 20s from now: $1" >&2
        exit 1
    fi
    mark "scenario start, waiting until $1 UTC"
    sleep $(( START - NOW - 10 ))     # 경계 10초 전까지. 아래 wait_boundary가 그 경계 + 5초에 맞춘다
else
    mark "scenario start, waiting for next 5-min boundary"
fi
wait_boundary; mark "slot1 start: ping -c 20";             ping -c 20 "$TARGET" > /dev/null;          mark "slot1 end"
wait_boundary; mark "slot2 start: nmap -sT -p 1-1000";     nmap -sT -p 1-1000 "$TARGET" > /dev/null;  mark "slot2 end"
wait_boundary; mark "slot3 start: nmap -sV -p 1-200";      nmap -sV -p 1-200 "$TARGET" > /dev/null;   mark "slot3 end"
wait_boundary; mark "scenario end (last slot closed)"
echo "----- log: $LOG"
cat "$LOG"
