"""Gold v2 = Gold v1 18개 특징 + Zeek 프로토콜 로그 특징 24개(DD-006 수정 절 1번).

입력: Gold v1 창(outputs/gold/conn_features_v1), TGN 이벤트 표(outputs/events/tgn_v1, uid로 로그 요약이 붙은 conn).
출력: outputs/gold/conn_features_v2/{windows/, manifest.json}. 임시 폴더에 쓰고 다시 읽어 검사한 뒤 이름을 바꾼다.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets  # noqa: E402
from zeek_ad.gold_features import FEATURES as V1_FEATURES  # noqa: E402
from zeek_ad.log_features import KEYS, LOG_FEATURES, role_log_rows, window_log_features  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402
from zeek_ad.role_windows import scored_assets  # noqa: E402

FEATURE_VERSION = "conn-features.v2"
CODE_FILES = [PROJECT_ROOT / "zeek_ad" / f for f in ["log_features.py", "tgn_data.py", "role_windows.py", "assets.py"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold-v1", type=Path, default=PROJECT_ROOT / "outputs" / "gold" / "conn_features_v1")
    parser.add_argument("--events", type=Path, default=PROJECT_ROOT / "outputs" / "events" / "tgn_v1")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "gold" / "conn_features_v2")
    # 실습망(DD-012)은 configs/assets.lab.v1.json. 여러 개면 대역을 합친다. 기본값은 CIC 설정 하나(기존 동작).
    parser.add_argument("--assets", type=Path, nargs="+", default=[assets.PROJECT_CONFIG])
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        sys.exit(f"이미 있다: {project_path(out)}")
    tmp = out.with_name(out.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)

    spark = (SparkSession.builder.master("local[*]").appName("build-gold-v2")
             .config("spark.sql.session.timeZone", "UTC").config("spark.driver.memory", "8g").getOrCreate())
    spark.sparkContext.setLogLevel("ERROR")
    v1 = spark.read.parquet(str(args.gold_v1 / "windows"))
    events = spark.read.parquet(str(args.events / "events"))
    networks = assets.load_networks(args.assets)
    rows = role_log_rows(events, scored_assets(spark, events, networks))
    logf = window_log_features(rows)
    # 확인용: 이벤트 표로 센 역할 행 수가 Gold v1의 conn_count와 창마다 같아야 한다(같은 연결 집합).
    counts = rows.groupBy(*KEYS).agg(F.count("*").alias("event_rows"))

    v2 = (v1.join(logf, on=KEYS, how="left").join(counts, on=KEYS, how="left")
          .withColumn("feature_version", F.lit(FEATURE_VERSION)))
    v2.drop("event_rows").write.partitionBy("capture_id").mode("error").parquet(str(tmp / "windows"))

    written = spark.read.parquet(str(tmp / "windows"))
    check_rows = v2.agg(F.count("*").alias("n"),
                        F.sum((F.col("event_rows") != F.col("conn_count")).cast("int")).alias("count_mismatch"),
                        F.sum(F.col("event_rows").isNull().cast("int")).alias("no_events")).collect()[0]
    nulls = written.select([F.sum(F.col(c).isNull().cast("int")).alias(c) for c in LOG_FEATURES]).collect()[0].asDict()
    checks = {
        "rows_equal_v1": written.count() == v1.count(),
        "keys_unique": written.select(*KEYS).distinct().count() == written.count(),
        "event_rows_equal_conn_count": check_rows.count_mismatch == 0 and check_rows.no_events == 0,
        "log_features_not_null": all(v == 0 for v in nulls.values()),
    }
    nonzero = written.select([F.sum((F.col(c) > 0).cast("int")).alias(c) for c in LOG_FEATURES]).collect()[0].asDict()
    spark.stop()
    if not all(checks.values()):
        sys.exit(f"검사 실패: {checks} nulls={nulls}")

    manifest = {
        "gold_manifest_version": 1, "feature_version": FEATURE_VERSION,
        "feature_dictionary": "docs/feature-dictionary-v2.md",
        "features": V1_FEATURES + LOG_FEATURES, "v1_features": V1_FEATURES, "log_features": LOG_FEATURES,
        "inputs": [file_record(args.gold_v1 / "manifest.json"), file_record(args.events / "manifest.json")],
        "assets": [file_record(p) for p in args.assets],
        "code": [file_record(p) for p in CODE_FILES] + [file_record(Path(__file__).resolve())],
        "checks": checks, "windows": int(check_rows.n), "nonzero_windows": nonzero,
    }
    (tmp / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, out)
    print(json.dumps({"checks": checks, "windows": int(check_rows.n), "nonzero_windows": nonzero}, indent=1))


if __name__ == "__main__":
    main()
