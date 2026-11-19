"""자명한 기준선 B: 창마다 월요일 train에 없던 외부 상대 IP의 수(DD-006).

seen-set은 월요일 train 창에서만 만들고 평가 중에는 갱신하지 않는다.
"처음 보는 외부 목적지"라는 단순 규칙이 Recall을 얼마나 설명하는지 보려는 기준선이다.
"""

import argparse
import ipaddress
import json
from pathlib import Path
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets, windows  # noqa: E402
from zeek_ad.gold_features import KEYS  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402
from zeek_ad.role_windows import role_rows, scored_assets, with_window_start  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "detectors" / "new-external-peers.v1.json"
GOLD = PROJECT_ROOT / "outputs" / "gold" / "conn_features_v1"
TRAIN_CAPTURE = "cic17-mon"


def is_external(address, networks):
    # 내부 대역 밖이면 외부다. 내부 대역의 네트워크·브로드캐스트 주소는 외부가 아니다.
    ip = ipaddress.ip_address(address)
    return not any(ip in net for net in networks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "diagnostics" / "new_external_peers_v1")
    args = parser.parse_args()
    if args.out.exists():
        sys.exit(f"이미 있다: {project_path(args.out)}")
    config = json.loads(CONFIG.read_text(encoding="utf-8"))

    silver_manifests = sorted((args.silver / "_manifests").glob("*.json"))
    spark = (
        SparkSession.builder.master("local[*]").appName("new-external-peers")
        .config("spark.sql.session.timeZone", "UTC").getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    silver = spark.read.parquet(str(args.silver / "conn")).filter(
        F.col("capture_id").isin([p.stem for p in silver_manifests]))
    networks = assets.load_internal_networks(assets.PROJECT_CONFIG)
    w = windows.load_window_config(windows.PROJECT_CONFIG)["window_seconds"]
    rows = with_window_start(role_rows(silver, scored_assets(spark, silver, networks)), w)

    # 외부 판정은 작은 주소 표로 만들어 조인한다(규칙은 파이썬 한 곳에 둔다).
    peers = [r.peer_h for r in rows.select("peer_h").distinct().collect()]
    external = spark.createDataFrame([(p,) for p in sorted(peers) if is_external(p, networks)], "peer_h string")
    ext_rows = rows.join(F.broadcast(external), on="peer_h")

    # seen-set: 월요일 train 창의 외부 상대. 창 라벨은 Gold의 split을 그대로 쓴다.
    labels = spark.read.parquet(str(GOLD / "windows")).select(*KEYS, "split")
    train_keys = labels.filter((F.col("capture_id") == TRAIN_CAPTURE) & (F.col("split") == "train")).select(*KEYS)
    seen = ext_rows.join(F.broadcast(train_keys), on=KEYS).select("peer_h").distinct()
    seen_count = seen.count()

    new_rows = ext_rows.join(F.broadcast(seen), on="peer_h", how="left_anti")
    col = config["score_column"]
    scores = new_rows.groupBy(*KEYS).agg(F.countDistinct("peer_h").alias(col))
    scores.write.mode("error").parquet(str(args.out / "windows"))

    stats = (spark.read.parquet(str(args.out / "windows")).groupBy("capture_id")
             .agg(F.count("*").alias("windows_with_new"), F.sum(col).alias("new_peer_sum"))
             .orderBy("capture_id").collect())
    for r in stats:
        print(f"{r.capture_id}: windows_with_new={r.windows_with_new} new_peer_sum={r.new_peer_sum}")
    print(f"seen external peers (mon train) = {seen_count}, external peers total = {external.count()}")
    (args.out / "manifest.json").write_text(json.dumps({
        "config": file_record(CONFIG), "inputs": [file_record(p) for p in silver_manifests],
        "gold_manifest": file_record(GOLD / "manifest.json"),
        "code": [file_record(Path(__file__).resolve())],
        "seen_external_peers": seen_count,
        "counts": [r.asDict() for r in stats], "deployable": False,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    spark.stop()


if __name__ == "__main__":
    main()
