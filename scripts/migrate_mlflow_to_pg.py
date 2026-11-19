"""MLflow 백엔드를 SQLite(outputs/mlflow/mlflow.db)에서 PostgreSQL mlflow DB로 한 번 옮긴다(설계 7.1절, 단계 4).

MLflow에는 백엔드 간 이전 도구가 없다. 같은 MLflow 버전이 만든 표 구조(alembic 버전)가 같으므로 표를 그대로 복사한다.
- PostgreSQL 쪽 표는 MLflow가 처음 접속할 때 만든다. 그때 생기는 기본 행(Default 실험 등)은 SQLite 값으로 바꾼다.
- artifact는 파일 경로(outputs/mlflow/artifacts)를 그대로 가리키므로 옮기지 않는다.
- SQLite 파일은 지우지 않는다(백업). 옮긴 뒤 run·metric·param·tag 수와 metric 값 전체를 대조한다.
"""

from pathlib import Path
import sys

import sqlalchemy as sa

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import mlflow_tracking_uri  # noqa: E402

SQLITE = PROJECT_ROOT / "outputs" / "mlflow" / "mlflow.db"


def convert(value, column):
    # SQLite는 불리언을 0/1 정수로 저장한다. PostgreSQL boolean 열에는 bool로 넣는다.
    if value is not None and isinstance(column.type, sa.Boolean):
        return bool(value)
    return value


def main():
    import mlflow
    from mlflow.tracking import MlflowClient

    uri = mlflow_tracking_uri()
    MlflowClient(tracking_uri=uri).search_experiments()  # 첫 접속에서 MLflow가 표를 만든다
    src = sa.create_engine(f"sqlite:///{SQLITE}")
    dst = sa.create_engine(uri)
    src_meta, dst_meta = sa.MetaData(), sa.MetaData()
    src_meta.reflect(src)
    dst_meta.reflect(dst)
    with src.connect() as s:
        versions = (s.execute(sa.text("SELECT version_num FROM alembic_version")).scalar(),)
    with dst.connect() as d:
        if d.execute(sa.text("SELECT version_num FROM alembic_version")).scalar() != versions[0]:
            sys.exit("두 백엔드의 MLflow 표 버전이 다르다")
        if d.execute(sa.text("SELECT count(*) FROM runs")).scalar():
            sys.exit("PostgreSQL 쪽에 이미 run이 있다. 한 번만 옮긴다")

    counts = {}
    with src.connect() as s, dst.begin() as d:  # 전체를 한 트랜잭션으로 옮긴다
        tables = [t for t in dst_meta.sorted_tables if t.name != "alembic_version" and t.name in src_meta.tables]
        # 기본 행을 지운다(자식 표부터). 그다음 부모 표부터 넣는다.
        for t in reversed(tables):
            d.execute(t.delete())
        for t in tables:
            rows = s.execute(src_meta.tables[t.name].select()).mappings().all()
            if rows:
                d.execute(t.insert(), [{c.name: convert(r.get(c.name), c) for c in t.columns if c.name in r}
                                       for r in rows])
            counts[t.name] = len(rows)
        # 실험 번호 자동 증가 값을 옮긴 최댓값 뒤로 맞춘다.
        d.execute(sa.text("SELECT setval(pg_get_serial_sequence('experiments', 'experiment_id'), "
                          "(SELECT max(experiment_id) FROM experiments))"))
    print({k: v for k, v in counts.items() if v})

    # 대조: MLflow API로 두 백엔드를 읽어 run별 param·tag·metric 이력이 같은지 본다.
    old, new = MlflowClient(tracking_uri=f"sqlite:///{SQLITE}"), MlflowClient(tracking_uri=uri)
    mismatch = 0
    runs = old.search_runs([e.experiment_id for e in old.search_experiments()], max_results=10000)
    for r in runs:
        n = new.get_run(r.info.run_id)
        same = (n.data.params == r.data.params and n.data.tags == r.data.tags and n.data.metrics == r.data.metrics
                and n.info.artifact_uri == r.info.artifact_uri)
        for key in r.data.metrics:
            a = [(m.step, m.value, m.timestamp) for m in old.get_metric_history(r.info.run_id, key)]
            b = [(m.step, m.value, m.timestamp) for m in new.get_metric_history(r.info.run_id, key)]
            same = same and sorted(a) == sorted(b)
        mismatch += not same
    print(f"runs={len(runs)} mismatch={mismatch} mlflow={mlflow.__version__}")
    if mismatch:
        sys.exit("대조 실패")


if __name__ == "__main__":
    main()
