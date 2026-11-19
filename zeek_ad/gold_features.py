"""역할 행을 (캡처, 자산, 역할, 5분 창)으로 묶어 특징을 계산한다.

정의는 docs/feature-dictionary-v1.md를 따른다. 값은 변환 전 그대로 둔다(log1p·대치는 모델 전처리).
"""

from pyspark.sql import functions as F

FEATURE_VERSION = "conn-features.v1"
KEYS = ["capture_id", "asset_id", "role", "window_start"]
# 연결이 정상으로 성립하지 않은 Zeek conn_state.
UNESTABLISHED_STATES = ["S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR", "OTH"]
FEATURES = [
    "conn_count", "out_bytes_sum", "in_bytes_sum", "out_pkts_sum", "in_pkts_sum",
    "peer_count", "peer_port_count",
    "tcp_ratio", "udp_ratio", "icmp_ratio", "unestablished_ratio", "rejected_ratio",
    "duration_p50", "duration_p95", "duration_missing_ratio",
    "dns_ratio", "service_unidentified_ratio", "non_dns_conn_count",
]
RATIOS = [f for f in FEATURES if f.endswith("_ratio")]


def ratio(condition):
    # 조건이 참인 연결의 비율. 분모는 창의 연결 수다. 조건이 null이면 거짓으로 센다.
    return F.avg(F.when(condition, 1.0).otherwise(0.0))


def window_features(rows):
    """역할 행(role_windows.role_rows + window_start)에서 창마다 특징 한 행을 만든다."""
    # service는 "ssl,http"처럼 여러 개일 수 있다. 쉼표로 나눈 목록에 dns가 있는지 본다. 없으면(null) 거짓.
    is_dns = F.coalesce(F.array_contains(F.split(F.col("service"), ","), "dns"), F.lit(False))
    return rows.groupBy(*KEYS, "processing_run_id").agg(
        F.count("*").alias("conn_count"),
        # sum은 null을 건너뛴다. 창의 모든 값이 null이면 결과도 null이다(0이 아니다).
        F.sum("out_bytes").alias("out_bytes_sum"),
        F.sum("in_bytes").alias("in_bytes_sum"),
        F.sum("out_pkts").alias("out_pkts_sum"),
        F.sum("in_pkts").alias("in_pkts_sum"),
        F.countDistinct("peer_h").alias("peer_count"),
        F.countDistinct("peer_p").alias("peer_port_count"),
        ratio(F.col("proto") == "tcp").alias("tcp_ratio"),
        ratio(F.col("proto") == "udp").alias("udp_ratio"),
        ratio(F.col("proto") == "icmp").alias("icmp_ratio"),
        ratio(F.col("conn_state").isin(UNESTABLISHED_STATES)).alias("unestablished_ratio"),
        ratio(F.col("conn_state") == "REJ").alias("rejected_ratio"),
        # 정확한 분위수(선형 보간). null은 빼고 계산하고, 모두 null이면 null이다.
        F.percentile("duration", 0.5).alias("duration_p50"),
        F.percentile("duration", 0.95).alias("duration_p95"),
        ratio(F.col("duration").isNull()).alias("duration_missing_ratio"),
        ratio(is_dns).alias("dns_ratio"),
        ratio(F.col("service").isNull()).alias("service_unidentified_ratio"),
        F.sum(F.when(is_dns, 0).otherwise(1)).alias("non_dns_conn_count"),
        # 진단 열. 모델 입력이 아니다(DD-003).
        F.sum(F.col("eof_candidate").cast("int")).alias("eof_candidate_count"),
    )
