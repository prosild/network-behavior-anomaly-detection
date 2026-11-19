# zeek_AD 파이프라인 이미지(DD-015 배포 VM). 감시 프로그램·다시 계산·채점·근거·에이전트·근거 API가 이 이미지로 돈다.
#
# 바탕: Zeek 공식 이미지(configs/zeek/run.v2.json의 digest와 같다). Debian 13이라 Python 3.13이 기본으로 있다.
#   그래서 Zeek를 컨테이너 안에서 바로 부른다(ZEEKAD_ZEEK_RUNNER=local). Docker 소켓을 넘기지 않는다.
# 더하는 것: Java 21(Spark), capinfos(wireshark-common), tcpdump(같은 이미지를 수집 컨테이너에도 쓴다),
#   Python 패키지(deploy/pipeline/requirements.runtime.txt, 버전은 constraints.runtime.txt로 개발 환경과 같게).
# 코드·설정은 이미지에 넣고, 데이터(outputs/, data/)는 볼륨으로 붙인다. 비밀값은 환경 변수로 받는다(이미지에 넣지 않는다).
# 빌드(프로젝트 루트): docker build -f deploy/pipeline/Dockerfile -t zeekad-pipeline:dev .
FROM zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv openjdk-21-jre-headless wireshark-common tcpdump \
 && rm -rf /var/lib/apt/lists/*

# 패키지는 가상 환경에 설치한다(시스템 Python을 건드리지 않는다). torch는 CPU 빌드를 먼저 넣는다.
RUN python3 -m venv /opt/venv
ENV PATH=/opt/venv/bin:/usr/local/zeek/bin:$PATH
COPY deploy/pipeline/requirements.runtime.txt deploy/pipeline/constraints.runtime.txt /tmp/req/
RUN pip install --no-cache-dir torch==2.15.0 --index-url https://download.pytorch.org/whl/cpu \
 && pip install --no-cache-dir -r /tmp/req/requirements.runtime.txt -c /tmp/req/constraints.runtime.txt

# 일반 계정으로 돈다. 볼륨(outputs/, data/)은 이 계정(uid 1000)이 쓸 수 있어야 한다.
RUN useradd --uid 1000 --create-home zeekad
WORKDIR /app
COPY --chown=zeekad:zeekad zeek_ad/ zeek_ad/
COPY --chown=zeekad:zeekad scripts/ scripts/
COPY --chown=zeekad:zeekad configs/ configs/
COPY --chown=zeekad:zeekad db/ db/
COPY --chown=zeekad:zeekad tests/ tests/
USER zeekad
ENV PYTHONPATH=/app \
    ZEEKAD_ZEEK_RUNNER=local \
    SPARK_LOCAL_IP=127.0.0.1 \
    MLFLOW_DISABLE_AGENT_HINT=1 \
    PYTHONUNBUFFERED=1
CMD ["python", "scripts/live_watcher.py"]
