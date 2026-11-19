#!/bin/bash
# 처음 한 번 실행된다. 역할(계정)과 데이터베이스를 만든다. 표는 scripts/db_migrate.py가 만든다.
# 역할을 나누는 이유: 쓰는 쪽(worker), 읽는 쪽(API), 대시보드(뷰만 읽기)의 권한을 따로 제한한다.
# zeekad_dashboard: Java 대시보드 자체 데이터(사용자·역할·세션·감사 로그). dashboard_app이 소유하고 표는 Java(Flyway)가 만든다.
#   dashboard_app은 zeekad·mlflow DB에 접속할 수 없다(Q51).
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username postgres <<SQL
CREATE ROLE zeekad_owner  LOGIN PASSWORD '${ZEEKAD_OWNER_PASSWORD}';
CREATE ROLE zeekad_worker LOGIN PASSWORD '${ZEEKAD_WORKER_PASSWORD}';
CREATE ROLE zeekad_api    LOGIN PASSWORD '${ZEEKAD_API_PASSWORD}';
CREATE ROLE dashboard_ro  LOGIN PASSWORD '${DASHBOARD_RO_PASSWORD}';
CREATE ROLE dashboard_rw  LOGIN PASSWORD '${DASHBOARD_RW_PASSWORD}';
CREATE ROLE mlflow        LOGIN PASSWORD '${MLFLOW_DB_PASSWORD}';
CREATE ROLE dashboard_app LOGIN PASSWORD '${DASHBOARD_APP_PASSWORD}';

CREATE DATABASE zeekad OWNER zeekad_owner;
CREATE DATABASE mlflow OWNER mlflow;
CREATE DATABASE zeekad_dashboard OWNER dashboard_app;
-- 기본으로 모든 역할이 접속할 수 있다. 필요한 역할만 남긴다.
REVOKE ALL ON DATABASE zeekad FROM PUBLIC;
REVOKE ALL ON DATABASE mlflow FROM PUBLIC;
REVOKE ALL ON DATABASE zeekad_dashboard FROM PUBLIC;
GRANT CONNECT ON DATABASE zeekad TO zeekad_worker, zeekad_api, dashboard_ro, dashboard_rw;
SQL

# public 스키마에 아무나 표를 만들지 못하게 한다. 앱 표는 zeekad 스키마에 둔다.
psql -v ON_ERROR_STOP=1 --username postgres --dbname zeekad <<SQL
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA zeekad AUTHORIZATION zeekad_owner;
SQL
