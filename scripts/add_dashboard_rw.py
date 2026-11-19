"""이미 초기화된 DB에 대시보드 상태 변경 계정(dashboard_rw)을 더한다. 새로 만드는 DB는 deploy/postgres/init/01이 만든다.

관리자(postgres) 계정으로 127.0.0.1에 접속한다. 비밀번호는 deploy/.env에서 읽고 출력하지 않는다. 여러 번 실행해도 된다.
이 계정이 할 수 있는 것은 migration 008의 dashboard.transition_incident 실행뿐이다.
예: python scripts/add_dashboard_rw.py
"""

from pathlib import Path
import sys

import psycopg
from psycopg import sql

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import load_env  # noqa: E402


def main():
    env = load_env()
    pw = env.get("DASHBOARD_RW_PASSWORD")
    if not pw:
        sys.exit("deploy/.env에 DASHBOARD_RW_PASSWORD가 없다")
    with psycopg.connect(host="127.0.0.1", port=int(env.get("POSTGRES_PORT", 55432)), dbname="postgres",
                         user="postgres", password=env["POSTGRES_SUPERUSER_PASSWORD"], autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = 'dashboard_rw'").fetchone()
        verb = "ALTER" if exists else "CREATE"
        conn.execute(sql.SQL(verb + " ROLE dashboard_rw LOGIN PASSWORD {}").format(sql.Literal(pw)))
        conn.execute("GRANT CONNECT ON DATABASE zeekad TO dashboard_rw")
    print(f"dashboard_rw {'갱신' if exists else '생성'}")


if __name__ == "__main__":
    main()
