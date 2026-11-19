"""Gold 창 몇 개를 골라, Silver 원래 행에서 pandas·numpy로 특징을 다시 계산해 대조한다.

Spark 코드(role_windows, gold_features)를 쓰지 않고 따로 계산한다. 두 계산이 같으면 정의대로 구현된 것이다.
"""

import argparse
import math
from pathlib import Path
import sys

import numpy as np
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.gold_features import FEATURES, UNESTABLISHED_STATES  # noqa: E402

# 손계산용 관점 변환. role_windows.PERSPECTIVE를 쓰지 않고 따로 적는다.
SIDES = {
    "originator": dict(asset="orig_h", peer="resp_h", peer_p="resp_p", out_b="orig_bytes",
                       in_b="resp_bytes", out_p="orig_pkts", in_p="resp_pkts"),
    "responder": dict(asset="resp_h", peer="orig_h", peer_p="orig_p", out_b="resp_bytes",
                      in_b="orig_bytes", out_p="resp_pkts", in_p="orig_pkts"),
}


def expected_features(d, side):
    """창 하나의 Silver 행(pandas)으로 특징 사전의 정의를 그대로 계산한다."""
    n = len(d)
    is_dns = d["service"].fillna("").str.split(",").apply(lambda s: "dns" in s)

    def total(col):
        # 모두 결측이면 None(null). 0이 아니다.
        return None if d[col].isna().all() else float(d[col].sum())

    dur = d["duration"].dropna().to_numpy()
    return {
        "conn_count": n,
        "out_bytes_sum": total(side["out_b"]), "in_bytes_sum": total(side["in_b"]),
        "out_pkts_sum": total(side["out_p"]), "in_pkts_sum": total(side["in_p"]),
        "peer_count": d[side["peer"]].nunique(), "peer_port_count": d[side["peer_p"]].nunique(),
        "tcp_ratio": (d["proto"] == "tcp").sum() / n,
        "udp_ratio": (d["proto"] == "udp").sum() / n,
        "icmp_ratio": (d["proto"] == "icmp").sum() / n,
        "unestablished_ratio": d["conn_state"].isin(UNESTABLISHED_STATES).sum() / n,
        "rejected_ratio": (d["conn_state"] == "REJ").sum() / n,
        # numpy 기본 분위수는 선형 보간이다.
        "duration_p50": float(np.percentile(dur, 50)) if len(dur) else None,
        "duration_p95": float(np.percentile(dur, 95)) if len(dur) else None,
        "duration_missing_ratio": d["duration"].isna().sum() / n,
        "dns_ratio": is_dns.sum() / n,
        "service_unidentified_ratio": d["service"].isna().sum() / n,
        "non_dns_conn_count": int((~is_dns).sum()),
    }


def same(a, b):
    if a is None or b is None or (isinstance(a, float) and math.isnan(a)):
        return a is None and b is None
    return abs(float(a) - float(b)) <= 1e-9 * max(1.0, abs(float(b)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gold", type=Path, default=PROJECT_ROOT / "outputs" / "gold" / "conn_features_v1")
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    parser.add_argument("--capture-id", default="cic17-mon")
    parser.add_argument("--samples", type=int, default=6)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    spark = SparkSession.builder.master("local[*]").appName("check-gold").getOrCreate()
    spark.sparkContext.setLogLevel("ERROR")
    gold = spark.read.parquet(str(args.gold / "windows")).filter(F.col("capture_id") == args.capture_id)
    silver = spark.read.parquet(str(args.silver / "conn")).filter(F.col("capture_id") == args.capture_id)

    # 고르는 창: 역할별 연결 수가 가장 많은 창, duration이 전부 결측인 창(null 경로), 무작위 창.
    picks = []
    for role in SIDES:
        picks += gold.filter(F.col("role") == role).orderBy(F.desc("conn_count")).limit(1).collect()
    picks += gold.filter("duration_missing_ratio = 1").limit(1).collect()
    picks += gold.orderBy(F.rand(args.seed)).limit(args.samples).collect()

    failures = 0
    for g in picks:
        side = SIDES[g["role"]]
        d = silver.filter(
            (F.col(side["asset"]) == g["asset_id"])
            & (F.col("write_ts") >= g["window_start"]) & (F.col("write_ts") < g["window_end"])
        ).toPandas()
        exp = expected_features(d, side)
        bad = [f for f in FEATURES if not same(g[f], exp[f])]
        failures += bool(bad)
        print(f"{g['role']:10s} {g['asset_id']:15s} start={g['window_start']} split={g['split']:14s} "
              f"conn={g['conn_count']:6d} -> {'OK' if not bad else 'MISMATCH ' + str(bad)}")
        for f in bad:
            print(f"    {f}: gold={g[f]} expected={exp[f]}")
    print(f"checked={len(picks)} mismatched={failures}")
    spark.stop()


if __name__ == "__main__":
    main()
