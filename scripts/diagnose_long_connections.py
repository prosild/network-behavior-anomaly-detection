"""긴 연결이 월요일 보류 구간의 상위 점수 창을 차지하는지 진단한다(설계 4.3절 필수 진단).

1. 창마다 가장 큰 연결 하나의 바이트 점유율과 그 연결의 지속시간.
2. 지속시간 300초 초과 연결이 창 바이트의 절반 이상인 창의 비율.
3. 모델별 상위 N 창에서 그런 창이 차지하는 비율.
특징을 고치거나 지우려는 것이 아니라 해석의 문제를 찾기 위한 진단이다.
"""

import argparse
import json
from pathlib import Path
import sys

import pandas as pd
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets, windows  # noqa: E402
from zeek_ad.gold_features import KEYS  # noqa: E402
from zeek_ad.role_windows import role_rows, scored_assets, with_window_start  # noqa: E402

LONG_SECONDS = 300


def window_byte_stats(silver_root):
    spark = (SparkSession.builder.master("local[*]").appName("long-conn")
             .config("spark.sql.session.timeZone", "UTC").getOrCreate())
    spark.sparkContext.setLogLevel("ERROR")
    silver = spark.read.parquet(str(silver_root / "conn")).filter(F.col("capture_id") == "cic17-mon")
    networks = assets.load_internal_networks(assets.PROJECT_CONFIG)
    w = windows.load_window_config(windows.PROJECT_CONFIG)["window_seconds"]
    rows = with_window_start(role_rows(silver, scored_assets(spark, silver, networks)), w)
    rows = rows.withColumn("bytes", F.coalesce(F.col("out_bytes"), F.lit(0)) + F.coalesce(F.col("in_bytes"), F.lit(0)))
    stats = rows.groupBy(*KEYS).agg(
        F.sum("bytes").alias("total_bytes"),
        F.max("bytes").alias("max_conn_bytes"),
        # 가장 큰 연결의 지속시간. (바이트, 지속시간) 구조체의 최댓값은 바이트가 큰 쪽이다.
        F.max(F.struct("bytes", "duration")).getField("duration").alias("max_conn_duration"),
        F.sum(F.when(F.col("duration") > LONG_SECONDS, F.col("bytes")).otherwise(0)).alias("long_bytes"),
    ).toPandas()
    spark.stop()
    total = stats.total_bytes.where(stats.total_bytes > 0)
    stats["max_conn_share"] = stats.max_conn_bytes / total
    stats["long_share"] = stats.long_bytes / total
    return stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scores", type=Path, nargs="+", help="run_baselines.py의 scores.parquet")
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    parser.add_argument("--top", type=int, nargs="+", default=[10, 20])
    args = parser.parse_args()

    stats = window_byte_stats(args.silver)
    report = {}
    for path in args.scores:
        model = path.parent.name.split("-", 1)[1]
        s = pd.read_parquet(path)
        hold = s[(s.capture_id == "cic17-mon") & (s.split == "holdout")].merge(
            stats, on=["capture_id", "asset_id", "role", "window_start"])
        hold["long_dominated"] = hold.long_share >= 0.5
        hold = hold.sort_values("score", ascending=False)
        r = {"holdout_windows": len(hold), "long_dominated_share_all": round(hold.long_dominated.mean(), 4)}
        for n in args.top:
            top = hold.head(n)
            r[f"top{n}_long_dominated_share"] = round(top.long_dominated.mean(), 4)
            r[f"top{n}_median_max_conn_share"] = round(top.max_conn_share.median(), 4)
        r["top10"] = hold.head(10)[["asset_id", "role", "window_start", "score", "total_bytes",
                                    "max_conn_share", "max_conn_duration", "long_share"]].round(4).to_dict("records")
        report[model] = r
        print(f"\n== {model}: holdout={len(hold)} long-dominated(all)={r['long_dominated_share_all']:.3f} "
              + " ".join(f"top{n}={r[f'top{n}_long_dominated_share']:.2f}" for n in args.top))
        print(hold.head(10)[["asset_id", "role", "window_start", "score", "total_bytes", "max_conn_share",
                             "max_conn_duration", "long_share"]].round(3).to_string(index=False))
    out = PROJECT_ROOT / "outputs" / "diagnostics" / "long_connections.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    print(f"\nreport={out.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
