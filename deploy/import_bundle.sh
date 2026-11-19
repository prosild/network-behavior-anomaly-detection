#!/bin/bash
# 배포 묶음 가져오기(DD-015, 배포 VM에서 실행). deploy/export_bundle.sh가 만든 묶음을 받는다.
#
# 순서
# 1. 해시 확인(SHA256SUMS).
# 2. Postgres만 띄운다. 다른 서비스가 돌고 있으면 멈춘다(MLflow 화면이 빈 DB에 자기 표를 먼저 만들면 복원이 충돌한다).
# 3. 두 DB가 비어 있는지 확인한다. 이미 표가 있으면 아무것도 하지 않는다(덮어쓰지 않는다).
# 4. pg_restore: 계정은 초기화 스크립트(postgres/init)가 VM의 .env 비밀번호로 이미 만들었다. 표 주인·권한이 그대로 살아난다.
#    --single-transaction: 실패하면 그 DB는 빈 채로 남는다.
# 5. MLflow DB 안의 이 PC 절대 경로를 컨테이너 경로로 바꾼다. 모든 문자열 열을 훑어 바꾸고, 남은 곳이 0인지 확인한다.
#    <old_root>/mlruns/... → /app/outputs/mlflow/mlruns/... (trace 실험의 기본 위치. 볼륨 안에 두어 지워지지 않게 한다)
#    <old_root>/...        → /app/...
#    모델 파일(MLmodel 등)은 고치지 않는다. 그 안의 경로는 기록일 뿐이고, 불러올 때는 모델 폴더 안의 파일을 쓴다.
# 6. 파일을 프로젝트 폴더(ZEEKAD_ROOT, 기본은 이 스크립트의 상위 폴더)에 푼다.
#
# 사용(프로젝트 루트): deploy/import_bundle.sh <묶음 폴더>
# 리허설: COMPOSE_PROJECT_NAME·POSTGRES_PORT·ZEEKAD_ROOT 환경 변수로 다른 Compose 프로젝트·포트·폴더에 가져올 수 있다.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
BUNDLE=$(cd "${1:?"묶음 폴더를 준다"}" && pwd -P)
DATA_ROOT=${ZEEKAD_ROOT:-$ROOT}
DC=(docker compose -f "$ROOT/deploy/compose.yaml" --env-file "$ROOT/deploy/.env")

echo "1. 해시 확인"
(cd "$BUNDLE" && sha256sum -c --quiet SHA256SUMS)
OLD_ROOT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["old_root"])' "$BUNDLE/manifest.json")
NEW_ROOT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["new_root"])' "$BUNDLE/manifest.json")

echo "2. Postgres만 띄우기 (Compose 프로젝트: $("${DC[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])'))"
running=$("${DC[@]}" --profile app ps --services --status running | grep -vx postgres || true)
if [ -n "$running" ]; then
    echo "먼저 멈춘다: $running  (docker compose ... --profile app stop $running)" >&2
    exit 1
fi
"${DC[@]}" up -d --wait postgres

psql_su() { "${DC[@]}" exec -T postgres psql -U postgres -v ON_ERROR_STOP=1 -At "$@"; }

echo "3. 빈 DB인지 확인"
for db in zeekad mlflow; do
    n=$(psql_su -d "$db" -c "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')")
    if [ "$n" != 0 ]; then
        echo "$db DB에 이미 표가 ${n}개 있다. 가져오지 않는다." >&2
        exit 1
    fi
done

echo "4. 복원"
for db in zeekad mlflow; do
    "${DC[@]}" exec -T postgres pg_restore -U postgres -d "$db" --clean --if-exists --exit-on-error --single-transaction \
        < "$BUNDLE/db/$db.dump"
    echo "  $db: 표 $(psql_su -d "$db" -c "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema')")개"
done

echo "5. MLflow 경로 바꾸기: $OLD_ROOT → $NEW_ROOT"
psql_su -d mlflow -v old="$OLD_ROOT" -v new="$NEW_ROOT" <<'SQL'
SELECT set_config('zeekad.old', :'old', false) AS o, set_config('zeekad.new', :'new', false) AS n \gset
DO $$
DECLARE
    c record;
    n bigint;
    old text := current_setting('zeekad.old');
    new text := current_setting('zeekad.new');
BEGIN
    FOR c IN SELECT table_schema, table_name, column_name FROM information_schema.columns
             WHERE table_schema = 'public' AND data_type IN ('text', 'character varying')
    LOOP
        EXECUTE format('UPDATE %I.%I SET %I = replace(replace(%I, $1, $2), $3, $4) WHERE strpos(%I, $3) > 0',
                       c.table_schema, c.table_name, c.column_name, c.column_name, c.column_name)
            USING old || '/mlruns/', new || '/outputs/mlflow/mlruns/', old || '/', new || '/';
        GET DIAGNOSTICS n = ROW_COUNT;
        IF n > 0 THEN
            RAISE NOTICE '%.%: %행', c.table_name, c.column_name, n;
        END IF;
    END LOOP;
END $$;
SQL
for db in zeekad mlflow; do
    left=$(psql_su -d "$db" -v old="$OLD_ROOT" <<'SQL'
SELECT set_config('zeekad.old', :'old', false) AS o \gset
DO $$
DECLARE c record; n bigint; total bigint := 0;
BEGIN
    FOR c IN SELECT table_schema, table_name, column_name FROM information_schema.columns
             WHERE table_schema NOT IN ('pg_catalog', 'information_schema') AND data_type IN ('text', 'character varying', 'jsonb', 'json')
    LOOP
        EXECUTE format('SELECT count(*) FROM %I.%I WHERE strpos(%I::text, $1) > 0', c.table_schema, c.table_name, c.column_name)
            INTO n USING current_setting('zeekad.old');
        total := total + n;
    END LOOP;
    PERFORM set_config('zeekad.left', total::text, false);
END $$;
SELECT current_setting('zeekad.left');
SQL
)
    left=$(echo "$left" | tail -1)
    echo "  $db: 이 PC 경로가 남은 값 ${left}개"
    [ "$left" = 0 ] || { echo "경로가 남았다" >&2; exit 1; }
done

echo "6. 파일 풀기 → $DATA_ROOT"
tar -xf "$BUNDLE/files.tar" -C "$DATA_ROOT"
mkdir -p "$DATA_ROOT/data/live/inbox" "$DATA_ROOT/data/live/spool"
echo "끝. 다음: docker compose -f deploy/compose.yaml --env-file deploy/.env --profile app up -d"
