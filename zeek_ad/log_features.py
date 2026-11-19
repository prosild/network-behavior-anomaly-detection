"""Zeek 프로토콜 로그 창 특징(conn-features.v2의 추가분, DD-006 수정 절 1번).

입력은 TGN 이벤트 표(outputs/events/tgn_v1)다. conn 한 행에 uid로 dns·http·ssl·ssh·ftp·smb·kerberos·dce_rpc·ntlm
요약이 붙어 있다. 이것을 (capture_id, asset_id, role, window_start)로 모은다.
- 모든 특징은 "그 로그가 없으면 0"인 개수·최댓값이다. 비율은 쓰지 않는다(분모가 0인 창이 많다).
- 역할별로 따로 센다. 예: ssh_auth_fail_count는 originator면 보낸 실패, responder면 받은 실패다.
정의는 docs/feature-dictionary-v2.md를 따른다.
"""

from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType

from zeek_ad.assets import ORIGINATOR, RESPONDER
from zeek_ad.tgn_data import entropy

KEYS = ["capture_id", "asset_id", "role", "window_start"]
COMMON_QTYPES = ["A", "AAAA", "PTR"]
LOG_FEATURES = [
    "dns_query_count", "dns_unique_query_count", "dns_query_len_max", "dns_query_entropy_max",
    "dns_nxdomain_count", "dns_rare_qtype_count",
    "http_request_count", "http_error_count", "http_uri_len_max", "http_uri_special_max",
    "http_user_agent_count", "http_host_count",
    "ssl_conn_count", "ssl_sni_count", "ssl_no_sni_count", "ssl_not_established_count",
    "ssh_auth_fail_count", "ssh_auth_attempts_sum",
    "ftp_fail_count",
    "smb_map_count", "smb_file_count", "dce_op_count", "krb_fail_count", "ntlm_fail_count",
]
ASSET_COLUMN = {ORIGINATOR: "orig_h", RESPONDER: "resp_h"}
LOG_COLUMNS = ["dns_n", "dns_query", "dns_qtype", "dns_query_len_max", "dns_nxdomain_n", "http_n", "http_error_n",
               "http_uri_len_max", "http_uri_special_max", "http_user_agent", "http_host", "ssl_version",
               "ssl_established", "ssl_sni", "ssh_auth_success", "ssh_auth_attempts", "ftp_fail_n", "smb_map_n",
               "smb_file_n", "dce_n", "krb_fail_n", "ntlm_fail_n"]


def role_log_rows(events, assets):
    """이벤트 한 행을 0~2개의 (자산, 역할) 행으로 펼친다. 로그 요약 열은 역할과 무관하게 그대로 옮긴다."""
    parts = []
    for role, key in ASSET_COLUMN.items():
        matched = events.join(F.broadcast(assets.withColumnRenamed("asset_id", key)), on=key)
        parts.append(matched.select("capture_id", F.col(key).alias("asset_id"), F.lit(role).alias("role"),
                                    "window_start", *LOG_COLUMNS))
    return parts[0].unionByName(parts[1])


def count_if(cond):
    return F.sum(F.when(cond, 1).otherwise(0))


def total(col):
    # 없는 값(null)은 0으로 더한다. 창에 그 로그가 하나도 없으면 0이다.
    return F.coalesce(F.sum(col), F.lit(0))


def largest(col):
    return F.coalesce(F.max(col), F.lit(0))


def window_log_features(rows):
    """역할 행에서 창마다 로그 특징 24개를 만든다."""
    query_entropy = F.udf(lambda q: entropy(q) if q else 0.0, DoubleType())
    has_ssl = F.col("ssl_version").isNotNull() | F.col("ssl_established").isNotNull()
    return rows.groupBy(*KEYS).agg(
        total("dns_n").alias("dns_query_count"),
        F.countDistinct("dns_query").alias("dns_unique_query_count"),
        largest("dns_query_len_max").alias("dns_query_len_max"),
        largest(query_entropy("dns_query")).alias("dns_query_entropy_max"),
        total("dns_nxdomain_n").alias("dns_nxdomain_count"),
        count_if(F.col("dns_qtype").isNotNull() & ~F.col("dns_qtype").isin(COMMON_QTYPES)).alias("dns_rare_qtype_count"),
        total("http_n").alias("http_request_count"),
        total("http_error_n").alias("http_error_count"),
        largest("http_uri_len_max").alias("http_uri_len_max"),
        largest("http_uri_special_max").alias("http_uri_special_max"),
        F.countDistinct("http_user_agent").alias("http_user_agent_count"),
        F.countDistinct("http_host").alias("http_host_count"),
        count_if(has_ssl).alias("ssl_conn_count"),
        F.countDistinct("ssl_sni").alias("ssl_sni_count"),
        count_if(has_ssl & F.col("ssl_sni").isNull()).alias("ssl_no_sni_count"),
        count_if(has_ssl & ~F.coalesce(F.col("ssl_established"), F.lit(False))).alias("ssl_not_established_count"),
        count_if(F.col("ssh_auth_success") == False).alias("ssh_auth_fail_count"),  # noqa: E712 (Spark 식)
        total("ssh_auth_attempts").alias("ssh_auth_attempts_sum"),
        total("ftp_fail_n").alias("ftp_fail_count"),
        total("smb_map_n").alias("smb_map_count"),
        total("smb_file_n").alias("smb_file_count"),
        total("dce_n").alias("dce_op_count"),
        total("krb_fail_n").alias("krb_fail_count"),
        total("ntlm_fail_n").alias("ntlm_fail_count"),
    )
