"""Bronze conn.log를 명시적 스키마로 읽고 기본 품질을 확인한다. 아무것도 쓰지 않는다."""

import argparse
from pathlib import Path
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zeek_ad.conn_schema import CONN_FIELDS, CONN_SCHEMA  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("conn_log", type=Path)
    args = parser.parse_args()

    spark = (
        SparkSession.builder.master("local[*]").appName("inspect-conn")
        # 시각을 문자열로 보여 줄 때 컴퓨터 시간대(한국)가 아니라 UTC를 쓴다.
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    path = str(args.conn_log.resolve())

    # 1. 명시적 스키마로 읽기. Spark가 타입을 추측하지 않는다.
    conn = spark.read.schema(CONN_SCHEMA).option("mode", "PERMISSIVE").json(path)
    conn.cache()
    total = conn.count()
    corrupt = conn.filter(F.col("_corrupt_record").isNotNull()).count()
    print(f"rows={total} corrupt={corrupt}")

    # 2. 스키마에 없는 필드 확인. 명시적 스키마는 모르는 필드를 조용히 버리기 때문이다.
    keys = (
        spark.read.text(path)
        .select(F.explode(F.json_object_keys("value")).alias("key"))
        .distinct().collect()
    )
    unknown = sorted({row.key for row in keys} - set(CONN_FIELDS))
    print(f"unknown_fields={unknown}")

    # 3. 필드가 없는 행(null)과 값이 0인 행을 따로 센다.
    for name in ["duration", "orig_bytes", "resp_bytes", "service", "history"]:
        missing = conn.filter(F.col(name).isNull()).count()
        zero = conn.filter(F.col(name) == 0).count() if name != "service" and name != "history" else "-"
        print(f"{name}: missing={missing} zero={zero}")

    # 4. 앞의 3행을 사람이 읽기 쉬운 UTC 시각으로 보기. 점이 든 열 이름은 backtick으로 감싼다.
    conn.select(
        F.timestamp_seconds("ts").alias("ts_utc"),
        F.timestamp_seconds("_write_ts").alias("write_ts_utc"),
        "`id.orig_h`", "`id.resp_h`", "`id.resp_p`", "proto", "conn_state", "duration",
    ).show(3, truncate=False)

    spark.stop()


if __name__ == "__main__":
    main()
