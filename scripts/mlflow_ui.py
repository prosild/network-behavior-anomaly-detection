"""MLflow 화면(UI)을 띄운다. 백엔드는 PostgreSQL mlflow DB, 주소는 http://127.0.0.1:5000 이다.

DB 비밀번호가 명령줄(다른 사용자가 ps로 볼 수 있음)에 드러나지 않도록 환경 변수로 넘긴다.
인자를 주면 기본값(--host 127.0.0.1 --port 5000) 대신 그대로 mlflow server에 넘긴다.
컨테이너(Compose, DD-015) 예: --host 0.0.0.0 --port 5000 --workers 1 --cors-allowed-origins http://<관리 주소>:5000
끌 때는 Ctrl+C.
"""

import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import mlflow_tracking_uri  # noqa: E402


def main():
    env = {**os.environ, "MLFLOW_BACKEND_STORE_URI": mlflow_tracking_uri()}
    # 기존 run의 artifact는 run마다 기록된 파일 경로에서 읽는다.
    args = sys.argv[1:] or ["--host", "127.0.0.1", "--port", "5000"]
    os.execvpe("mlflow", ["mlflow", "server", *args], env)


if __name__ == "__main__":
    main()
