"""이미 초기화된 DB 서버에 Java 대시보드 자체 DB(zeekad_dashboard)와 소유 계정(dashboard_app)을 더한다(Q51).

새로 만드는 DB 서버는 deploy/postgres/init/01이 만든다. 이 스크립트는 그 내용을 지금 서버에 맞춘다. 여러 번 실행해도 된다.
1. deploy/.env에 DASHBOARD_APP_PASSWORD가 없으면 무작위 값을 덧붙인다(파일 권한 600 유지). 값은 출력하지 않는다.
2. 관리자(postgres)로 127.0.0.1에 접속해 계정을 만들거나 비밀번호를 맞추고, 데이터베이스를 만든다(소유자 dashboard_app).
3. 다른 계정이 이 DB에 접속하지 못하게 PUBLIC 권한을 거둔다. dashboard_app은 zeekad·mlflow에 접속 권한이 없다
   (두 DB는 처음부터 PUBLIC 접속을 거뒀고 이 계정에 따로 주지 않는다).
예: python scripts/add_dashboard_app.py
"""

from pathlib import Path
import secrets
import sys

import psycopg
from psycopg import sql

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import ENV_FILE, load_env  # noqa: E402

KEY, ROLE, DB = "DASHBOARD_APP_PASSWORD", "dashboard_app", "zeekad_dashboard"


def ensure_password():
    if KEY in load_env():
        return False
    text = ENV_FILE.read_text(encoding="utf-8")
    text += ("" if text.endswith("\n") else "\n") + \
        "# Java 대시보드 자체 DB(zeekad_dashboard) 소유 계정. zeekad DB에는 접속할 수 없다\n" + \
        f"{KEY}={secrets.token_urlsafe(24)}\n"
    ENV_FILE.write_text(text, encoding="utf-8")
    ENV_FILE.chmod(0o600)
    return True


def main():
    added = ensure_password()
    env = load_env()
    with psycopg.connect(host="127.0.0.1", port=int(env.get("POSTGRES_PORT", 55432)), dbname="postgres",
                         user="postgres", password=env["POSTGRES_SUPERUSER_PASSWORD"], autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (ROLE,)).fetchone()
        verb = "ALTER" if exists else "CREATE"
        conn.execute(sql.SQL(verb + " ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(ROLE), sql.Literal(env[KEY])))
        if not conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB,)).fetchone():
            conn.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(DB), sql.Identifier(ROLE)))
            db_state = "생성"
        else:
            conn.execute(sql.SQL("ALTER DATABASE {} OWNER TO {}").format(sql.Identifier(DB), sql.Identifier(ROLE)))
            db_state = "이미 있음(소유자 확인)"
        conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(DB)))
    print(f".env 비밀번호 {'추가' if added else '이미 있음'} · 계정 {ROLE} {'갱신' if exists else '생성'} · DB {DB} {db_state}")


if __name__ == "__main__":
    main()
