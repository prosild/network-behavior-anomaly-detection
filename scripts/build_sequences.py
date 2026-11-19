"""Gold 창 특징으로 Transformer 입력 시퀀스를 만든다(DD-002, configs/models/transformer.v1.json).

출력: outputs/sequences/transformer_v1/
- sequences.npz: x (행 수, K, 21), y (행 수, 18)
- index.parquet: 행마다 capture_id, asset_id, role, window_start, split (Gold와 같은 순서)
- manifest.json: 입력·설정·코드 해시, 전처리 값, 개수
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.baselines import Preprocessor  # noqa: E402
from zeek_ad.gold_features import FEATURES, KEYS  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402
from zeek_ad.sequences import MARKER_COLUMNS, Scaler, build_sequences  # noqa: E402
from zeek_ad.windows import load_window_config, PROJECT_CONFIG  # noqa: E402

BOUNDS = PROJECT_ROOT / "manifests" / "cic-ids-2017.capture-bounds.v1.json"
CONFIG = PROJECT_ROOT / "configs" / "models" / "transformer.v1.json"
CODE_FILES = [PROJECT_ROOT / "zeek_ad" / f for f in ["sequences.py", "baselines.py"]] + [Path(__file__).resolve()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    # v1 설정에는 inputs 절이 없다. 그때는 v1 경로를 쓴다.
    inputs = config.get("inputs", {})
    gold_dir = PROJECT_ROOT / inputs.get("gold", "outputs/gold/conn_features_v1")
    out_dir = PROJECT_ROOT / inputs.get("sequences", "outputs/sequences/transformer_v1")
    if out_dir.exists():
        sys.exit(f"이미 있다: {project_path(out_dir)}")
    features = json.loads((gold_dir / "manifest.json").read_text(encoding="utf-8")).get("features", FEATURES)
    token_columns = features + MARKER_COLUMNS
    k = config["sequence"]["context_windows"]
    w = load_window_config(PROJECT_CONFIG)["window_seconds"]
    bounds = json.loads(BOUNDS.read_text(encoding="utf-8"))["captures"]
    first_slot = {c["capture_id"]: int(float(c["packet_time_min"]) // w * w) for c in bounds}

    gold = pd.read_parquet(gold_dir / "windows")
    gold["capture_id"] = gold["capture_id"].astype(str)
    gold = gold.sort_values(KEYS).reset_index(drop=True)
    train = gold[gold.split == "train"]

    # 전처리와 표준화는 train 행으로만 적합한다.
    pre = Preprocessor(features).fit(train)
    scaler = Scaler().fit(pre.transform(train)[features].to_numpy())
    z = scaler.transform(pre.transform(gold)[features].to_numpy())
    role = (gold["role"] == "responder").to_numpy(dtype=float)
    keys = list(gold[KEYS].itertuples(index=False, name=None))
    x, y = build_sequences(keys, z, role, first_slot, w, k)

    # 검증: 결측이 없고, train 대상의 표준화 값은 평균 0이다.
    checks = {
        "no_nan": bool(np.isfinite(x).all() and np.isfinite(y).all()),
        "train_target_mean_near_zero": bool(np.abs(y[gold.split == "train"].mean(axis=0)).max() < 1e-4),
        "one_marker_per_token": bool(((x[:, :, -2] + x[:, :, -1]) <= 1).all()),
    }
    if not all(checks.values()):
        sys.exit(f"검증 실패: {checks}")

    tmp = out_dir.with_name(out_dir.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    np.savez_compressed(tmp / "sequences.npz", x=x, y=y)
    gold[KEYS + ["split"]].to_parquet(tmp / "index.parquet", index=False)

    # 디스크에서 다시 읽어 같은지 확인한 뒤 공개한다.
    back = np.load(tmp / "sequences.npz")
    if not (np.array_equal(back["x"], x) and np.array_equal(back["y"], y)):
        sys.exit("다시 읽은 배열이 다르다")
    marker = {s: {"inactive_share": round(float(x[gold.split == s][:, :, -2].mean()), 4),
                  "outside_share": round(float(x[gold.split == s][:, :, -1].mean()), 4)}
              for s in sorted(gold.split.unique())}
    manifest = {
        "config": file_record(config_path), "gold_manifest": file_record(gold_dir / "manifest.json"),
        "bounds": file_record(BOUNDS), "code": [file_record(p) for p in CODE_FILES],
        "shape": {"x": list(x.shape), "y": list(y.shape)}, "token_columns": token_columns,
        "target_columns": features, "first_slot": first_slot,
        "rows_by_split": gold.split.value_counts().sort_index().to_dict(),
        "marker_share_by_split": marker, "checks": checks,
        "preprocess": pre.params(), "scaler": scaler.params(features),
        "outputs": [file_record(tmp / f) for f in ["sequences.npz", "index.parquet"]],
    }
    for o in manifest["outputs"]:
        o["path"] = o["path"].replace(tmp.name, out_dir.name)
    (tmp / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, out_dir)

    print(f"x={x.shape} y={y.shape} -> {project_path(out_dir)}")
    print(json.dumps({"rows_by_split": manifest["rows_by_split"], "markers": marker, "checks": checks}, indent=2))


if __name__ == "__main__":
    main()
