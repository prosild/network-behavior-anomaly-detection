#!/bin/bash
# 처음 한 번 실행된다. pgvector 확장은 신뢰(trusted) 확장이 아니라 superuser만 만들 수 있다.
# public 스키마에 확장만 두고, 앱 역할에는 USAGE(사용)만 준다. CREATE(새 객체 만들기)는 막힌 그대로다.
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username postgres --dbname zeekad <<SQL
CREATE EXTENSION IF NOT EXISTS vector;
GRANT USAGE ON SCHEMA public TO zeekad_owner, zeekad_worker, zeekad_api;
SQL
