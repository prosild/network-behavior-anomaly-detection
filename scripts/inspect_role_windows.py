"""Silver를 자산·역할 관측으로 펼치고 창 수를 센다. 아무것도 쓰지 않는다.

월요일 창 수를 설계 6.1절의 사전 점검 수치(출발 958·235, 수신 328·77)와 대조한다.
"""

import argparse
from pathlib import Path
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets, windows  # noqa: E402
from zeek_ad.role_windows import (  # noqa: E402
    load_captures, role_rows, scored_assets, window_labels, with_window_start,
)

CAPTURES_CONFIG = PROJECT_ROOT / "configs" / "captures.cic-ids-2017.v1.json"
BOUNDS_MANIFEST = PROJECT_ROOT / "manifests" / "cic-ids-2017.capture-bounds.v1.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    parser.add_argument("--explain", action="store_true", help="역할 행의 실행 계획을 출력한다")
    args = parser.parse_args()

    # manifest가 있는 캡처만 완료된 Silver다.
    completed = sorted(p.stem for p in (args.silver / "_manifests").glob("*.json"))
    print(f"completed_captures={completed}")

    spark = (
        SparkSession.builder.master("local[*]").appName("inspect-role-windows")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")

    # capture_id는 폴더 이름에서 만들어진 열이라, 이 filter는 해당 폴더만 읽게 한다(partition pruning).
    silver = spark.read.parquet(str(args.silver / "conn")).filter(F.col("capture_id").isin(completed))
    silver.cache()

    networks = assets.load_internal_networks(assets.PROJECT_CONFIG)
    window_config = windows.load_window_config(windows.PROJECT_CONFIG)
    w = window_config["window_seconds"]
    captures = load_captures(CAPTURES_CONFIG, BOUNDS_MANIFEST)

    scored = scored_assets(spark, silver, networks)
    rows = with_window_start(role_rows(silver, scored), w)
    if args.explain:
        rows.explain()
    rows.cache()

    # 1. 연결 하나가 몇 개의 역할 행이 됐는지. 0이면 양쪽 모두 점수화 대상이 아니다.
    per_conn = rows.groupBy("capture_id", "source_row_number").count()
    two = per_conn.filter("count = 2").count()
    one = per_conn.filter("count = 1").count()
    total = silver.count()
    print(f"scored_assets={scored.count()} silver_rows={total} role_rows={rows.count()}")
    print(f"connections: two_roles={two} one_role={one} zero_roles={total - two - one}")

    # 2. 창 하나 = (캡처, 자산, 역할, 창 시작). 연결이 하나라도 있는 창만 생긴다(설계 3.2절).
    labels = window_labels(spark, rows, captures, w, window_config["split_fraction"])
    asset_windows = (
        rows.select("capture_id", "asset_id", "role", "window_start").distinct()
        .join(labels, on=["capture_id", "window_start"])
    )
    (asset_windows.groupBy("capture_id", "role")
     .pivot("split", ["train", "holdout", "split_boundary", "capture_edge",
                      "development", "retrospective_eval"])
     .count().na.fill(0)
     .orderBy("capture_id", "role")
     .show(truncate=False))
    spark.stop()


if __name__ == "__main__":
    main()
