"""완료된 Silver 캡처 전체로 Gold 창 특징을 만들고, 검증을 통과하면 폴더를 게시한다.

임시 폴더(<out>.tmp)에 다 쓰고 검증한 뒤 manifest를 넣고, 마지막에 폴더 이름을 바꾼다.
그래서 <out>이 있으면 완성·검증된 결과다.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets, windows  # noqa: E402
from zeek_ad.gold_features import FEATURE_VERSION, FEATURES, KEYS, RATIOS, window_features  # noqa: E402
from zeek_ad.role_windows import (  # noqa: E402
    load_captures, role_rows, scored_assets, window_labels, with_window_start,
)

CAPTURES_CONFIG = PROJECT_ROOT / "configs" / "captures.cic-ids-2017.v1.json"
BOUNDS_MANIFEST = PROJECT_ROOT / "manifests" / "cic-ids-2017.capture-bounds.v1.json"
CODE_FILES = [
    PROJECT_ROOT / "zeek_ad" / "assets.py",
    PROJECT_ROOT / "zeek_ad" / "windows.py",
    PROJECT_ROOT / "zeek_ad" / "role_windows.py",
    PROJECT_ROOT / "zeek_ad" / "gold_features.py",
    PROJECT_ROOT / "scripts" / "build_gold.py",
]


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_path(path):
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path)


def file_record(path):
    return {"path": project_path(path), "size_bytes": path.stat().st_size, "sha256": sha256(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "gold" / "conn_features_v1")
    # 합성 캡처(DD-008)는 configs/synthetic/captures.syn1.v1.json과 outputs/synthetic/apt_v1/capture-bounds.json.
    parser.add_argument("--captures", type=Path, default=CAPTURES_CONFIG)
    parser.add_argument("--bounds", type=Path, default=BOUNDS_MANIFEST)
    # 실습망(DD-012)은 configs/assets.lab.v1.json. 여러 개면 대역을 합친다. 기본값은 CIC 설정 하나(기존 동작).
    parser.add_argument("--assets", type=Path, nargs="+", default=[assets.PROJECT_CONFIG])
    args = parser.parse_args()
    config_files = [*(p.resolve() for p in args.assets), windows.PROJECT_CONFIG, args.captures.resolve(), args.bounds.resolve()]

    silver_root, out = args.silver.resolve(), args.out.resolve()
    if out.exists():
        sys.exit(f"이미 있다: {project_path(out)}")
    tmp = out.with_name(out.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)  # 지난 실행이 중간에 멈춘 흔적이다. 완료 결과가 아니므로 지운다.

    # manifest가 있는 캡처만 완료된 Silver다.
    silver_manifests = sorted((silver_root / "_manifests").glob("*.json"))
    completed = [p.stem for p in silver_manifests]
    print(f"completed_captures={completed}")

    spark = (
        SparkSession.builder.master("local[*]").appName("build-gold")
        .config("spark.sql.session.timeZone", "UTC")
        # 정확한 분위수는 창마다 duration 값을 모두 메모리에 모은다. 기본 1GB로는 12개 작업이 동시에 돌 때 부족했다.
        # local 모드에서는 driver가 executor를 겸하므로 driver 메모리를 늘린다. JVM 시작 전에만 적용된다.
        .config("spark.driver.memory", "8g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")

    silver = spark.read.parquet(str(silver_root / "conn")).filter(F.col("capture_id").isin(completed))
    networks = assets.load_networks(args.assets)
    window_config = windows.load_window_config(windows.PROJECT_CONFIG)
    w = window_config["window_seconds"]
    captures = load_captures(args.captures, args.bounds)

    rows = with_window_start(role_rows(silver, scored_assets(spark, silver, networks)), w)
    rows.cache()
    labels = window_labels(spark, rows, captures, w, window_config["split_fraction"])
    gold = (
        window_features(rows)
        .join(labels, on=["capture_id", "window_start"])
        .withColumn("window_end", F.col("window_start") + w)
        .withColumn("feature_version", F.lit(FEATURE_VERSION))
        .select(*KEYS, "window_end", "split", "feature_version", "processing_run_id",
                *FEATURES, "eof_candidate_count")
    )
    # partitionBy: capture_id 값마다 capture_id=<값> 폴더를 만들고, 파일 안에서는 그 열을 뺀다.
    gold.write.partitionBy("capture_id").mode("error").parquet(str(tmp / "windows"))

    # 검증은 디스크에 쓴 파일을 다시 읽어서 한다.
    written = spark.read.parquet(str(tmp / "windows"))
    role_row_count = rows.count()
    stats = written.agg(
        F.count("*").alias("windows"),
        F.countDistinct(*KEYS).alias("distinct_keys"),
        F.sum("conn_count").alias("conn_sum"),
        *[F.min(c).alias(f"{c}_min") for c in RATIOS],
        *[F.max(c).alias(f"{c}_max") for c in RATIOS],
    ).first()
    checks = {
        # 창으로 묶는 동안 역할 행이 빠지거나 두 번 세지지 않았다.
        "conn_count_sum_equals_role_rows": stats["conn_sum"] == role_row_count,
        # 키 하나에 행 하나.
        "keys_unique": stats["windows"] == stats["distinct_keys"],
        "ratios_within_0_1": all(0 <= stats[f"{c}_min"] and stats[f"{c}_max"] <= 1 for c in RATIOS),
    }
    counts = [
        r.asDict() for r in
        written.groupBy("capture_id", "role", "split").count().orderBy("capture_id", "role", "split").collect()
    ]
    print(f"role_rows={role_row_count} gold_windows={stats['windows']}")
    print(json.dumps(checks, indent=2))
    written.groupBy("capture_id", "role").pivot(
        "split", ["train", "holdout", "split_boundary", "capture_edge", "development", "retrospective_eval"]
    ).count().na.fill(0).orderBy("capture_id", "role").show(truncate=False)

    if not all(checks.values()):
        spark.stop()
        sys.exit(f"검증 실패. 게시하지 않았다. 임시 폴더: {project_path(tmp)}")

    manifest = {
        "gold_manifest_version": 1,
        "feature_version": FEATURE_VERSION,
        "feature_dictionary": "docs/feature-dictionary-v1.md",
        "inputs": [
            {**file_record(p), "capture_id": p.stem,
             "processing_run_id": json.loads(p.read_text(encoding="utf-8"))["processing_run_id"]}
            for p in silver_manifests
        ],
        "configs": [file_record(p) for p in config_files],
        "code": [file_record(p) for p in CODE_FILES],
        "runtime": {"spark_version": spark.version, "python_version": platform.python_version()},
        "role_rows": role_row_count,
        "windows": stats["windows"],
        "counts": counts,
        "checks": checks,
        "outputs": [file_record(p) for p in sorted((tmp / "windows").rglob("*.parquet"))],
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    spark.stop()

    # 경로는 게시 후 위치로 적는다.
    for o in manifest["outputs"]:
        o["path"] = o["path"].replace(project_path(tmp), project_path(out), 1)
    (tmp / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                                       encoding="utf-8")
    os.replace(tmp, out)  # 폴더 이름 바꾸기. 이 순간 완성된 결과가 게시된다.
    print(f"published={project_path(out)}")


if __name__ == "__main__":
    main()
