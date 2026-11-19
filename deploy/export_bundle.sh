#!/bin/bash
# 배포 묶음 내보내기(DD-015, 이 PC에서 실행). VM에서 deploy/import_bundle.sh로 가져간다.
#
# 묶음 = DB 두 개(zeekad, mlflow)의 덤프 + 실시간 처리에 필요한 파일만(약 50MB) + 코드(code.tar) + 해시 목록.
# - zeekad_dashboard DB는 넣지 않는다. Java 대시보드가 Flyway로 VM에서 새로 만든다(사용자·감사 로그는 환경마다 따로).
# - 비밀값(deploy/.env)은 넣지 않는다. VM에는 따로 옮긴다.
# - MLflow DB에는 이 PC의 절대 경로가 들어 있다. 여기서는 그대로 두고, 이 폴더 경로(old_root)를 manifest.json에 적는다.
#   가져올 때 컨테이너 경로(/app)로 바꾼다.
#
# 사용(프로젝트 루트): deploy/export_bundle.sh <출력 폴더>      예: deploy/export_bundle.sh ../zeekad-bundle-20261118
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
OUT=${1:?"출력 폴더를 준다(아직 없는 경로)"}
if [ -e "$OUT" ]; then
    echo "이미 있다: $OUT" >&2
    exit 1
fi
DC=(docker compose -f "$ROOT/deploy/compose.yaml" --env-file "$ROOT/deploy/.env")

# 실시간 처리(감시 프로그램·채점·에이전트)가 읽는 파일. 근거는 scripts/live_recompute.py, zeek_ad/agent_inputs.py.
FILES=(
    outputs/mlflow/artifacts                              # 배포 묶음 모델(zeekad-fusion)과 실험 기록 파일
    outputs/events/tgn_v1/manifest.json                   # 월요일 원래 이벤트: TGN 그래프의 앞부분(메모리 예열)
    outputs/events/tgn_v1/events/capture_id=cic17-mon
    outputs/graphs/tgn_v1/encoding.json                   # 실습망 그래프 인코딩이 월요일 것과 같은지 확인
    outputs/gold/conn_features_v2                         # LLM 입력의 비교 기준(월요일 정상 창)
    outputs/live/zeek                                     # 실습망 시험 데이터(DB의 ingest_file이 가리킨다)
    data/live/store
)

mkdir -p "$OUT/db"
for db in zeekad mlflow; do
    # 컨테이너 안에서 superuser로 덤프한다(소켓 접속, 비밀번호가 명령줄에 나오지 않는다). -Fc: pg_restore용 형식.
    "${DC[@]}" exec -T postgres pg_dump -U postgres -Fc -d "$db" > "$OUT/db/$db.dump"
done
(cd "$ROOT" && tar -cf "$OUT/files.tar" "${FILES[@]}")
# 코드: 이 프로젝트는 git 저장소가 아니라서 묶음에 넣는다. 이미지 빌드(.dockerignore)와 Compose 실행에 필요한 것만.
# deploy/.env(비밀값)는 넣지 않는다.
(cd "$ROOT" && tar -cf "$OUT/code.tar" --exclude=__pycache__ --exclude=deploy/.env \
    zeek_ad scripts configs db tests .dockerignore \
    deploy/compose.yaml deploy/.env.example deploy/postgres deploy/pipeline deploy/export_bundle.sh deploy/import_bundle.sh)

PG_VERSION=$("${DC[@]}" exec -T postgres psql -U postgres -Atc "SHOW server_version")
python3 - "$OUT/manifest.json" "$ROOT" "$PG_VERSION" "${FILES[@]}" <<'EOF'
import json, sys
from datetime import datetime, timezone
out, root, pg, *files = sys.argv[1:]
json.dump({"bundle_version": 1, "created_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "old_root": root, "new_root": "/app", "postgres_server_version": pg,
           "databases": ["zeekad", "mlflow"], "files": files,
           "note": "deploy/import_bundle.sh로 가져온다. MLflow DB의 old_root 경로를 new_root(컨테이너 경로)로 바꾼다."},
          open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
EOF
(cd "$OUT" && sha256sum db/zeekad.dump db/mlflow.dump files.tar code.tar manifest.json > SHA256SUMS)
du -sh "$OUT"/db/* "$OUT/files.tar" "$OUT/code.tar"
echo "끝: $OUT"
