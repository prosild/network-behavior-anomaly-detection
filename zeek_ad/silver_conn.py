"""Bronze conn.log를 Silver 표로 바꾼다. 한 행은 연결 하나다."""

from pyspark.sql import functions as F
from pyspark.sql.types import StructType

from zeek_ad.conn_schema import CONN_SCHEMA


# 점(.)이 든 Zeek 이름을 Spark에서 다루기 쉬운 이름으로 바꾼다.
RENAMES = {"id.orig_h": "orig_h", "id.orig_p": "orig_p", "id.resp_h": "resp_h", "id.resp_p": "resp_p",
           "_write_ts": "write_ts"}
PARSE_SCHEMA = StructType([f for f in CONN_SCHEMA.fields if f.name != "_corrupt_record"])


def read_with_row_numbers(spark, conn_path):
    """원문을 한 줄씩 읽고, 파일 안의 행 번호(1부터)를 붙인다."""
    # zipWithIndex는 파티션 순서와 파티션 안의 순서대로 번호를 매긴다. 텍스트 파일은 파일 순서와 같다.
    lines = spark.read.text(conn_path).rdd.zipWithIndex()
    return lines.map(lambda pair: (pair[1] + 1, pair[0].value)).toDF(["source_row_number", "raw"])


def build_silver_conn(spark, conn_path, capture_id, processing_run_id):
    """(silver, quarantine) 두 DataFrame을 돌려준다. 아무것도 쓰지 않는다."""
    lines = read_with_row_numbers(spark, conn_path)
    parsed = lines.withColumn(
        "rec", F.from_json("raw", PARSE_SCHEMA, {"mode": "PERMISSIVE"})
    )
    # ts가 없으면 연결 행으로 쓸 수 없다. 버리지 않고 원문과 함께 격리한다.
    bad = F.col("rec").isNull() | F.col("rec.ts").isNull() | F.col("rec._write_ts").isNull()
    quarantine = parsed.filter(bad).select(
        F.lit(capture_id).alias("capture_id"), F.lit(processing_run_id).alias("processing_run_id"),
        "source_row_number", "raw",
    )

    good = parsed.filter(~bad)
    columns = [F.col(f"rec.`{f.name}`").alias(RENAMES.get(f.name, f.name)) for f in PARSE_SCHEMA.fields]
    silver = good.select(
        F.lit(capture_id).alias("capture_id"),
        F.lit(processing_run_id).alias("processing_run_id"),
        "source_row_number",
        *columns,
    )

    # PCAP 끝에서 한꺼번에 기록됐을 수 있는 행. 마지막 기록 시각과 같으면 후보로 표시한다(DD-003).
    # network_time()은 줄지 않으므로, 이 실행의 최대 write_ts가 마지막으로 처리한 패킷 시각이다.
    last_write_ts = silver.agg(F.max("write_ts")).first()[0]
    silver = silver.withColumn("eof_candidate", F.col("write_ts") == F.lit(last_write_ts))
    return silver, quarantine
