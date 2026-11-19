"""Silver 연결을 자산·역할 관측으로 펼치고, 5분 창과 창 라벨을 붙인다.

판정 규칙은 assets.py와 windows.py 한 곳에만 둔다. Spark에서는 그 규칙으로 작은 표
(점수화 대상 주소, 창 라벨)를 만든 뒤 큰 표에 조인한다. 그래서 단위 테스트한 규칙과
Spark 결과가 어긋나지 않는다.
"""

import json
from pathlib import Path

from pyspark.sql import functions as F

from zeek_ad.assets import ORIGINATOR, RESPONDER, is_scored_asset
from zeek_ad.windows import label_window

# 역할별로 Zeek의 orig/resp 열을 자산 관점 열로 바꾼다(설계 3.2절).
# responder에서는 자산이 resp 쪽이므로 보낸·받은 방향이 뒤집힌다.
PERSPECTIVE = {
    ORIGINATOR: {"asset_id": "orig_h", "peer_h": "resp_h", "peer_p": "resp_p", "local_p": "orig_p",
                 "out_bytes": "orig_bytes", "in_bytes": "resp_bytes",
                 "out_pkts": "orig_pkts", "in_pkts": "resp_pkts"},
    RESPONDER: {"asset_id": "resp_h", "peer_h": "orig_h", "peer_p": "orig_p", "local_p": "resp_p",
                "out_bytes": "resp_bytes", "in_bytes": "orig_bytes",
                "out_pkts": "resp_pkts", "in_pkts": "orig_pkts"},
}
# 역할과 무관하게 그대로 옮기는 열.
SHARED = ["capture_id", "processing_run_id", "source_row_number", "uid", "ts", "write_ts",
          "proto", "service", "conn_state", "duration", "eof_candidate"]


def load_captures(config_path, bounds_path):
    """capture_id마다 용도와 패킷 시각 범위를 합친 dict를 돌려준다."""
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    bounds = json.loads(Path(bounds_path).read_text(encoding="utf-8"))
    by_id = {b["capture_id"]: b for b in bounds["captures"]}
    if set(by_id) != {c["capture_id"] for c in config["captures"]}:
        raise ValueError("captures 설정과 capture-bounds manifest의 capture_id가 다르다")
    return {
        c["capture_id"]: {"usage": c["usage"],
                          "packet_time_min": float(by_id[c["capture_id"]]["packet_time_min"]),
                          "packet_time_max": float(by_id[c["capture_id"]]["packet_time_max"])}
        for c in config["captures"]
    }


def scored_assets(spark, silver, networks):
    """Silver에 나온 주소 중 점수화 대상만 담은 작은 표(열: asset_id)."""
    addresses = (
        silver.select(F.col("orig_h").alias("address"))
        .union(silver.select(F.col("resp_h").alias("address")))
        .distinct().collect()
    )
    scored = sorted(r.address for r in addresses if is_scored_asset(r.address, networks))
    return spark.createDataFrame([(a,) for a in scored], "asset_id string")


def role_rows(silver, assets):
    """연결 하나를 0~2개의 (자산, 역할) 행으로 펼친다. 연결 자체는 지우지 않는다."""
    parts = []
    for role, cols in PERSPECTIVE.items():
        # 작은 주소 표를 모든 executor에 복사해 두고 조인한다(broadcast). 큰 표는 shuffle하지 않는다.
        key = cols["asset_id"]
        matched = silver.join(F.broadcast(assets.withColumnRenamed("asset_id", key)), on=key)
        parts.append(matched.select(
            *SHARED, F.lit(role).alias("role"),
            *[F.col(src).alias(dst) for dst, src in cols.items()],
        ))
    return parts[0].unionByName(parts[1])


def with_window_start(rows, window_seconds):
    # windows.window_start와 같은 식이다: floor(write_ts / w) * w. 배정 필드는 _write_ts다(설계 4.2절).
    return rows.withColumn(
        "window_start", (F.floor(F.col("write_ts") / window_seconds) * window_seconds).cast("long")
    )


def window_labels(spark, rows, captures, window_seconds, split_fraction):
    """캡처마다 실제로 나온 창의 라벨 표(열: capture_id, window_start, split)."""
    keys = rows.select("capture_id", "window_start").distinct().collect()
    labels = []
    for r in keys:
        c = captures[r.capture_id]
        labels.append((r.capture_id, r.window_start, label_window(
            r.window_start, window_seconds, c["packet_time_min"], c["packet_time_max"],
            c["usage"], split_fraction)))
    return spark.createDataFrame(labels, "capture_id string, window_start long, split string")
