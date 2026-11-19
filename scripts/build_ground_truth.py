"""동결한 정답 에피소드 조건을 Silver에 실행해 연결 대응표와 창 대응표를 만든다.

- connections: 에피소드에 속한 Silver 연결(capture_id, source_row_number).
- windows: 그 연결이 들어간 Gold 창 키(capture_id, asset_id, role, window_start). 평가기는 이 표로
  예측 사건과 에피소드를 대응한다. 창은 _write_ts로 정하므로 긴 연결도 기록 창으로 대응된다(설계 5.3).
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets, windows  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402
from zeek_ad.role_windows import (  # noqa: E402
    load_captures, role_rows, scored_assets, window_labels, with_window_start,
)

DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "ground-truth" / "cic17-episodes.v1.json"
CAPTURES_CONFIG = PROJECT_ROOT / "configs" / "captures.cic-ids-2017.v1.json"
BOUNDS_MANIFEST = PROJECT_ROOT / "manifests" / "cic-ids-2017.capture-bounds.v1.json"
CODE_FILES = [
    PROJECT_ROOT / "zeek_ad" / "assets.py",
    PROJECT_ROOT / "zeek_ad" / "windows.py",
    PROJECT_ROOT / "zeek_ad" / "role_windows.py",
    PROJECT_ROOT / "scripts" / "build_ground_truth.py",
]


def utc_epoch(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def rule_filter(rule):
    """규칙 하나를 Spark 조건식으로 바꾼다. 모든 조건을 AND로 묶는다."""
    cond = (
        (F.col("capture_id") == rule["capture_id"])
        & F.col("orig_h").isin(rule["orig_h"]) & F.col("resp_h").isin(rule["resp_h"])
        & (F.col("ts") >= utc_epoch(rule["ts_start_utc"])) & (F.col("ts") < utc_epoch(rule["ts_end_utc"]))
    )
    if "resp_p" in rule:
        cond = cond & F.col("resp_p").isin(rule["resp_p"])
    if "proto" in rule:
        cond = cond & (F.col("proto") == rule["proto"])
    return cond


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "ground_truth" / "cic17_v1")
    args = parser.parse_args()

    out = args.out.resolve()
    if out.exists():
        sys.exit(f"이미 있다: {project_path(out)}")
    tmp = out.with_name(out.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)

    config = json.loads(args.config.read_text(encoding="utf-8"))
    silver_manifests = sorted((args.silver / "_manifests").glob("*.json"))
    completed = [p.stem for p in silver_manifests]

    spark = (
        SparkSession.builder.master("local[*]").appName("build-ground-truth")
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.driver.memory", "8g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    silver = spark.read.parquet(str(args.silver / "conn")).filter(F.col("capture_id").isin(completed))
    silver.cache()

    # 1. 규칙마다 연결을 고르고 합친다. 같은 에피소드의 규칙끼리 겹친 연결은 한 번만 남긴다.
    parts = [
        silver.filter(rule_filter(rule)).select(
            F.lit(ep["episode_id"]).alias("episode_id"), "capture_id", "source_row_number")
        for ep in config["episodes"] for rule in ep["rules"]
    ]
    connections = parts[0]
    for p in parts[1:]:
        connections = connections.unionByName(p)
    connections = connections.distinct()
    connections.cache()

    # 2. 한 연결이 두 에피소드에 들어가면 조건이 겹친 것이다. 대응이 모호해지므로 멈춘다.
    overlap = (connections.groupBy("capture_id", "source_row_number").count()
               .filter("count > 1").count())

    # 3. 연결 → 역할 행 → 창. Gold와 같은 코드(role_windows)로 창을 정한다.
    networks = assets.load_internal_networks(assets.PROJECT_CONFIG)
    window_config = windows.load_window_config(windows.PROJECT_CONFIG)
    w = window_config["window_seconds"]
    rows = with_window_start(role_rows(silver, scored_assets(spark, silver, networks)), w)
    matched = rows.join(connections, on=["capture_id", "source_row_number"])
    labels = window_labels(spark, matched, load_captures(CAPTURES_CONFIG, BOUNDS_MANIFEST), w,
                           window_config["split_fraction"])
    episode_windows = (
        matched.groupBy("episode_id", "capture_id", "asset_id", "role", "window_start")
        .agg(F.count("*").alias("matched_conn_count"))
        .join(labels, on=["capture_id", "window_start"])
    )

    connections.write.mode("error").parquet(str(tmp / "connections"))
    episode_windows.write.mode("error").parquet(str(tmp / "windows"))

    # 4. 에피소드별 요약. 연결이 하나도 안 걸린 에피소드는 조건이 틀린 것이다.
    conn_counts = {r.episode_id: r["count"] for r in connections.groupBy("episode_id").count().collect()}
    win = spark.read.parquet(str(tmp / "windows"))
    win_stats = {
        r.episode_id: r.asDict() for r in win.groupBy("episode_id").agg(
            F.count("*").alias("windows"),
            F.countDistinct("asset_id", "role").alias("asset_roles"),
            F.sum(F.when(F.col("split") == "capture_edge", 1).otherwise(0)).alias("capture_edge_windows"),
            F.collect_set(F.concat_ws(":", "role", "asset_id")).alias("observed"),
        ).collect()
    }
    summary = []
    for ep in config["episodes"]:
        s = win_stats.get(ep["episode_id"], {})
        summary.append({
            "episode_id": ep["episode_id"], "scenario": ep["scenario"], "status": ep["status"],
            "connections": conn_counts.get(ep["episode_id"], 0), "windows": s.get("windows", 0),
            "asset_roles": s.get("asset_roles", 0), "capture_edge_windows": s.get("capture_edge_windows", 0),
            "observed": sorted(s.get("observed", [])),
        })
    for s in summary:
        print(f"{s['episode_id']} {s['status']:9s} {s['scenario']:34s} conn={s['connections']:7d} "
              f"windows={s['windows']:4d} asset_roles={s['asset_roles']:2d} edge={s['capture_edge_windows']}")
    checks = {
        "no_connection_in_two_episodes": overlap == 0,
        "every_episode_has_connections": all(s["connections"] > 0 for s in summary),
    }
    print(json.dumps(checks, indent=2))
    if not all(checks.values()):
        spark.stop()
        sys.exit(f"검증 실패(overlap={overlap}). 게시하지 않았다. 임시 폴더: {project_path(tmp)}")

    manifest = {
        "ground_truth_manifest_version": 1,
        "config": file_record(args.config),
        "inputs": [file_record(p) for p in silver_manifests],
        "code": [file_record(p) for p in CODE_FILES],
        "spark_version": spark.version,
        "episodes": summary,
        "checks": checks,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    spark.stop()
    (tmp / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                                       encoding="utf-8")
    os.replace(tmp, out)
    print(f"published={project_path(out)}")


if __name__ == "__main__":
    main()
