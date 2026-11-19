"""PostgreSQL 접속 도우미(단계 4). 비밀번호는 deploy/.env(또는 환경 변수)에서 읽는다. 코드에 넣지 않는다.

역할마다 계정이 다르다: zeekad_owner(표 만들기), zeekad_worker(점수·사건 쓰기), zeekad_api(읽기),
dashboard_ro(대시보드 뷰 읽기), dashboard_rw(사건 상태 변경 함수 실행만).
dashboard_app은 Java 대시보드 자체 DB(zeekad_dashboard)의 소유자다. 이 프로젝트 코드는 권한 확인에만 쓴다.
"""

import os

import psycopg

from zeek_ad.provenance import PROJECT_ROOT

ENV_FILE = PROJECT_ROOT / "deploy" / ".env"
PASSWORD_KEYS = {"zeekad_owner": "ZEEKAD_OWNER_PASSWORD", "zeekad_worker": "ZEEKAD_WORKER_PASSWORD",
                 "zeekad_api": "ZEEKAD_API_PASSWORD", "dashboard_ro": "DASHBOARD_RO_PASSWORD",
                 "dashboard_rw": "DASHBOARD_RW_PASSWORD", "dashboard_app": "DASHBOARD_APP_PASSWORD"}

# 파일이 없어도(컨테이너는 deploy/.env를 이미지에 넣지 않는다) 환경 변수에서 받는 값들.
ENV_KEYS = set(PASSWORD_KEYS.values()) | {"MLFLOW_DB_PASSWORD", "GEMINI_API_KEY", "POSTGRES_HOST", "POSTGRES_PORT"}


def load_env(path=ENV_FILE):
    """KEY=VALUE 줄을 읽는다. 이미 있는 환경 변수가 우선한다(운영에서는 파일 대신 환경 변수를 준다)."""
    values = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    values.update({k: v for k, v in os.environ.items() if k in values or k in ENV_KEYS})
    return values


def db_address(env=None):
    """(호스트, 포트). 이 PC에서는 127.0.0.1:55432, 컨테이너(Compose)에서는 POSTGRES_HOST=postgres, POSTGRES_PORT=5432."""
    env = env or load_env()
    return env.get("POSTGRES_HOST", "127.0.0.1"), int(env.get("POSTGRES_PORT", 55432))


def connect(role, dbname="zeekad", autocommit=False):
    """역할 계정으로 접속한다. with 블록을 쓰면 끝날 때 commit(예외면 rollback)하고 닫는다."""
    env = load_env()
    host, port = db_address(env)
    return psycopg.connect(host=host, port=port, dbname=dbname, user=role,
                           password=env[PASSWORD_KEYS[role]], autocommit=autocommit,
                           options="-c search_path=zeekad,public")  # public에는 pgvector 확장만 있다


def mlflow_tracking_uri():
    """MLflow 백엔드(PostgreSQL의 mlflow DB) 주소. 비밀번호가 들어 있으므로 출력하거나 기록하지 않는다."""
    env = load_env()
    host, port = db_address(env)
    return f"postgresql+psycopg://mlflow:{env['MLFLOW_DB_PASSWORD']}@{host}:{port}/mlflow"
