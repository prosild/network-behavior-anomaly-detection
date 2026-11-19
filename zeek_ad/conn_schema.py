"""Zeek 8.0.10 conn.log(JSON)의 명시적 스키마."""

from pyspark.sql.types import (
    BooleanType, DoubleType, IntegerType, LongType, StringType, StructField, StructType,
)


# 5일 로그 전체에서 실제로 나온 필드 22개다(2026-11-03 조사).
# duration·orig_bytes·resp_bytes·history·service는 행에 따라 필드 자체가 없다. 읽으면 null이 된다.
CONN_SCHEMA = StructType([
    # 시각은 Zeek가 double로 쓴 값을 그대로 둔다.
    # JSON에는 소수 1~7자리로 찍혀 있어서 Decimal(16,6)로 읽으면 일부 값이 바뀐다.
    StructField("_write_ts", DoubleType()),
    StructField("ts", DoubleType()),
    StructField("uid", StringType()),
    StructField("id.orig_h", StringType()),
    StructField("id.orig_p", IntegerType()),
    StructField("id.resp_h", StringType()),
    StructField("id.resp_p", IntegerType()),
    StructField("proto", StringType()),
    StructField("service", StringType()),
    StructField("duration", DoubleType()),
    # 바이트·패킷 수는 긴 연결에서 21억(int 최대)을 넘을 수 있어 long으로 읽는다.
    StructField("orig_bytes", LongType()),
    StructField("resp_bytes", LongType()),
    StructField("conn_state", StringType()),
    StructField("local_orig", BooleanType()),
    StructField("local_resp", BooleanType()),
    StructField("missed_bytes", LongType()),
    StructField("history", StringType()),
    StructField("orig_pkts", LongType()),
    StructField("orig_ip_bytes", LongType()),
    StructField("resp_pkts", LongType()),
    StructField("resp_ip_bytes", LongType()),
    StructField("ip_proto", IntegerType()),
    # JSON으로 해석하지 못한 행은 버리지 않고 이 열에 원문을 담는다.
    StructField("_corrupt_record", StringType()),
])

CONN_FIELDS = [f.name for f in CONN_SCHEMA.fields if f.name != "_corrupt_record"]
