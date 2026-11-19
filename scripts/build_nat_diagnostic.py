"""NAT 편향 진단용 창 특징: 창마다 상대가 172.16.0.1인 연결 수(설계 6.1절).

배포하지 않는 진단이다. "공격 주소를 안다"는 정보만으로 얼마나 맞히는지 보여, 모델 결과 중
주소 지식으로 설명되는 몫을 드러낸다. 주소를 알게 된 경위는 docs/ground-truth-v1.md와
설계 3.2절에 공개한다(데이터셋 설명과 사전 탐색).
"""

import argparse
import json
from pathlib import Path
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets, windows  # noqa: E402
from zeek_ad.gold_features import KEYS  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402
from zeek_ad.role_windows import role_rows, scored_assets, with_window_start  # noqa: E402

NAT_ADDRESS = "172.16.0.1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "diagnostics" / "nat_v1")
    args = parser.parse_args()
    if args.out.exists():
        sys.exit(f"이미 있다: {project_path(args.out)}")

    silver_manifests = sorted((args.silver / "_manifests").glob("*.json"))
    spark = (
        SparkSession.builder.master("local[*]").appName("nat-diagnostic")
        .config("spark.sql.session.timeZone", "UTC").getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    silver = spark.read.parquet(str(args.silver / "conn")).filter(
        F.col("capture_id").isin([p.stem for p in silver_manifests]))
    networks = assets.load_internal_networks(assets.PROJECT_CONFIG)
    w = windows.load_window_config(windows.PROJECT_CONFIG)["window_seconds"]
    rows = with_window_start(role_rows(silver, scored_assets(spark, silver, networks)), w)

    # Gold와 같은 키로 센다. NAT 연결이 없는 창은 0이다.
    nat = rows.groupBy(*KEYS).agg(
        F.sum(F.when(F.col("peer_h") == NAT_ADDRESS, 1).otherwise(0)).alias("nat_conn_count"))
    nat.write.mode("error").parquet(str(args.out / "windows"))
    stats = (spark.read.parquet(str(args.out / "windows")).groupBy("capture_id")
             .agg(F.count("*").alias("windows"), F.sum((F.col("nat_conn_count") > 0).cast("int")).alias("nat_windows"))
             .orderBy("capture_id").collect())
    for r in stats:
        print(f"{r.capture_id}: windows={r.windows} with_nat={r.nat_windows}")
    (args.out / "manifest.json").write_text(json.dumps({
        "nat_address": NAT_ADDRESS, "inputs": [file_record(p) for p in silver_manifests],
        "code": [file_record(Path(__file__).resolve())],
        "counts": [r.asDict() for r in stats], "deployable": False,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    spark.stop()


if __name__ == "__main__":
    main()
