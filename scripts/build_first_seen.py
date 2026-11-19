"""first-seen 탐지기 점수(DD-006 작업 2-1). 규칙은 zeek_ad/first_seen.py, 설정은 configs/detectors/first-seen*.json.

순서: 월요일 train으로 seen-set → 월요일 나머지 창은 고정 채점 → 보류 p95로 임계값 →
화·수·목·금을 시각 순으로 채점하며 경보 없는 항목만 지연 편입(날을 넘겨 이어 간다).
"""

import argparse
import ipaddress
import json
from pathlib import Path
import sys

import pandas as pd
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets, windows  # noqa: E402
from zeek_ad.evaluation import percentile  # noqa: E402
from zeek_ad.first_seen import ORIGINATOR, relation_item, score_static, score_streaming  # noqa: E402
from zeek_ad.gold_features import KEYS  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402
from zeek_ad.role_windows import role_rows, scored_assets, with_window_start  # noqa: E402

GOLD = PROJECT_ROOT / "outputs" / "gold" / "conn_features_v1"
TRAIN_CAPTURE = "cic17-mon"


def load_relation_rows(spark, silver_dir, networks, w):
    """역할 행을 (창 키, 상대, 받는 쪽 포트, 프로토콜)로 줄여 pandas로 가져온다."""
    manifests = sorted((silver_dir / "_manifests").glob("*.json"))
    silver = spark.read.parquet(str(silver_dir / "conn")).filter(F.col("capture_id").isin([p.stem for p in manifests]))
    rows = with_window_start(role_rows(silver, scored_assets(spark, silver, networks)), w)
    # 받는 쪽 포트: 자산이 출발이면 상대 포트, 자산이 도착이면 자기 포트. 출발 쪽 임시 포트는 버린다.
    rows = rows.withColumn("resp_port", F.when(F.col("role") == ORIGINATOR, F.col("peer_p")).otherwise(F.col("local_p")))
    df = rows.select(*KEYS, "peer_h", "resp_port", "proto").distinct().toPandas()
    df["capture_id"] = df["capture_id"].astype(str)
    return df, manifests


def build_items(df, networks, config):
    excluded = [ipaddress.ip_network(n) for n in config["exclude_peer_networks"]]
    peers = df["peer_h"].unique()
    internal = {p: any(ipaddress.ip_address(p) in n for n in networks) for p in peers}
    drop = {p for p in peers if any(ipaddress.ip_address(p) in n for n in excluded)}
    df = df[~df["peer_h"].isin(drop)]
    combos = df[["asset_id", "role", "peer_h", "proto", "resp_port"]].drop_duplicates()
    admin = set(config["remote_admin_groups"])
    mapped = {}
    for a, r, p, proto, port in combos.itertuples(index=False):
        port = None if pd.isna(port) else int(port)
        mapped[(a, r, p, proto, port)] = relation_item(a, r, p, internal[p], proto, port, config["weights"], admin)
    rows = {}
    for t in df.itertuples(index=False):
        port = None if pd.isna(t.resp_port) else int(t.resp_port)
        item, weight = mapped[(t.asset_id, t.role, t.peer_h, t.proto, port)]
        rows.setdefault((t.capture_id, t.asset_id, t.role, t.window_start), {})[item] = weight
    return rows, len(drop)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    args = parser.parse_args()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    out = PROJECT_ROOT / config["scores_dir"]
    if out.exists():
        sys.exit(f"이미 있다: {project_path(out)}")

    spark = (SparkSession.builder.master("local[*]").appName("first-seen")
             .config("spark.sql.session.timeZone", "UTC")
             .config("spark.sql.execution.arrow.pyspark.enabled", "true").getOrCreate())
    spark.sparkContext.setLogLevel("ERROR")
    networks = assets.load_internal_networks(assets.PROJECT_CONFIG)
    w = windows.load_window_config(windows.PROJECT_CONFIG)["window_seconds"]
    df, manifests = load_relation_rows(spark, args.silver, networks, w)
    spark.stop()

    rows, dropped_peers = build_items(df, networks, config)
    gold = pd.read_parquet(GOLD / "windows", columns=KEYS + ["split"])
    gold["capture_id"] = gold["capture_id"].astype(str)
    split = {tuple(k): s for *k, s in gold.itertuples(index=False)}
    if set(rows) - set(split):
        sys.exit("Gold에 없는 창이 있다")

    mon = {k: v for k, v in rows.items() if k[0] == TRAIN_CAPTURE}
    seen = set().union(*[v for k, v in mon.items() if split[k] == "train"])
    seen_init = len(seen)
    scored = score_static(mon, seen)
    holdout = [scored.get(k, (0.0, set()))[0] for k, s in split.items() if k[0] == TRAIN_CAPTURE and s == "holdout"]
    rule = config["threshold_rule"]
    threshold = max(percentile(holdout, rule["percentile"]), rule["minimum"])

    seen_after = {}
    for cap in config["update"]["carry_over_days"]:
        day = {k: v for k, v in rows.items() if k[0] == cap}
        scored.update(score_streaming(day, seen, threshold, config["update"]["delay_windows"], w))
        seen_after[cap] = len(seen)

    records = []
    for k, (score, new) in scored.items():
        records.append({**dict(zip(KEYS, k)), config["score_column"]: float(score), "new_items": len(new),
                        "new_internal": sum(i.startswith("I|") for i in new),
                        "new_external": sum(i.startswith("E|") for i in new)})
    table = pd.DataFrame(records)
    out.mkdir(parents=True)
    table.to_parquet(out / "windows", index=False)
    summary = table.merge(gold, on=KEYS).groupby(["capture_id", "split"]).agg(
        windows=(config["score_column"], "size"),
        nonzero=(config["score_column"], lambda s: int((s > 0).sum())),
        candidates=(config["score_column"], lambda s: int((s >= threshold).sum()))).reset_index()
    print(summary.to_string(index=False))
    print(f"seen_init={seen_init} threshold={threshold} seen_after={seen_after} dropped_peers={dropped_peers}")
    (out / "manifest.json").write_text(json.dumps({
        "config": file_record(config_path), "inputs": [file_record(p) for p in manifests],
        "gold_manifest": file_record(GOLD / "manifest.json"),
        "code": [file_record(Path(__file__).resolve()), file_record(PROJECT_ROOT / "zeek_ad" / "first_seen.py")],
        "seen_init": seen_init, "update_threshold": threshold, "seen_after": seen_after,
        "dropped_peers": dropped_peers, "summary": summary.to_dict("records"),
    }, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
