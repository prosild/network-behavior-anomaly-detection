#!/bin/bash
# 장애 복구 시험용 DB(zeekad_test)를 만든다. 운영 DB(zeekad)와 같은 역할·스키마 구조다. 시험 데이터만 담는다.
# 실행: bash deploy/postgres/create_test_db.sh  (그 뒤 python scripts/db_migrate.py --db zeekad_test)
set -euo pipefail
docker exec -i zeekad-postgres-1 psql -v ON_ERROR_STOP=1 -U postgres <<'SQL'
CREATE DATABASE zeekad_test OWNER zeekad_owner;
REVOKE ALL ON DATABASE zeekad_test FROM PUBLIC;
GRANT CONNECT ON DATABASE zeekad_test TO zeekad_worker, zeekad_api;
\c zeekad_test
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA zeekad AUTHORIZATION zeekad_owner;
SQL
