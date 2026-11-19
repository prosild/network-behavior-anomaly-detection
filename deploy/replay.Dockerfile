# 실습망 배경 트래픽 재생용 일회용 이미지(DD-017). 상시 서비스가 아니라 Compose에 넣지 않는다.
# 만들기(배포 VM, ~/zeek_AD): docker build -t zeekad-replay:dev -f deploy/replay.Dockerfile .
# 실행 방법은 scripts/lab_replay.sh 머리말.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpreplay iproute2 && rm -rf /var/lib/apt/lists/*
COPY scripts/lab_replay.sh /usr/local/bin/lab_replay.sh
ENTRYPOINT ["sh", "/usr/local/bin/lab_replay.sh"]
