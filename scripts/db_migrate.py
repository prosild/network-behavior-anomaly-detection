"""db/migrations/*.sql을 번호 순서로 적용한다. 적용한 파일은 zeekad.schema_migrations에 해시와 함께 남긴다.

- 이미 적용한 파일은 건너뛴다. 적용한 뒤 내용이 바뀌었으면 멈춘다(적용된 DB와 파일이 달라진다).
- 파일 하나를 한 트랜잭션으로 적용한다. 중간에 실패하면 그 파일 전체가 취소된다.
"""

import argparse
import hashlib
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect  # noqa: E402

MIGRATIONS = PROJECT_ROOT / "db" / "migrations"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default="zeekad", help="장애 복구 시험용 DB는 zeekad_test")
    args = parser.parse_args()
    with connect("zeekad_owner", dbname=args.db) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS zeekad.schema_migrations (
                            name text PRIMARY KEY, sha256 char(64) NOT NULL,
                            applied_at timestamptz NOT NULL DEFAULT now())""")
        conn.commit()
        applied = dict(conn.execute("SELECT name, sha256 FROM zeekad.schema_migrations").fetchall())
        for path in sorted(MIGRATIONS.glob("*.sql")):
            sql = path.read_text(encoding="utf-8")
            digest = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            if path.name in applied:
                if applied[path.name] != digest:
                    sys.exit(f"{path.name}: 적용한 뒤 파일이 바뀌었다. 새 번호의 파일로 변경을 추가한다")
                print(f"skip {path.name}")
                continue
            with conn.transaction():
                conn.execute(sql)
                conn.execute("INSERT INTO zeekad.schema_migrations (name, sha256) VALUES (%s, %s)",
                             (path.name, digest))
            print(f"applied {path.name}")


if __name__ == "__main__":
    main()
