"""합성 APT 주입 평가(DD-008): 이미 정한 모델을 다시 학습하지 않고 합성 캡처(syn1-*)에 점수를 매긴다.

- 꼬리 희귀도·IF: 같은 월요일 train 창, 같은 seed로 다시 적합한다(결정적). 원래 run의 월요일 점수와 같은지 확인한다.
- Transformer: 원래 run의 체크포인트를 불러온다. 전처리·표준화는 월요일 train으로 다시 적합하고, 월요일 점수가 같은지 확인한다.
- 임계값: 월요일 보류 p95(원래 run과 같아야 한다).
- 평가: zeek_ad/synthetic_eval.py. 주 지표는 CIC 사건을 뺀 큐, 보조 지표는 전체 큐.

결과는 outputs/eval/<stamp>-synthetic_apt_v1/와 MLflow(실험 zeek-ad-stage3)에 남긴다.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
import mlflow  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import torch  # noqa: E402
from torch.utils.data import DataLoader  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.baselines import IForest, Preprocessor, TailRarity  # noqa: E402
from zeek_ad.evaluation import TIE_KEY_VERSION  # noqa: E402
from zeek_ad.experiment import BOUNDS, EPISODES, TRUTH, holdout_threshold, setup_mlflow  # noqa: E402
from zeek_ad.gold_features import FEATURES, KEYS  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402
from zeek_ad.sequences import Scaler, build_sequences  # noqa: E402
from zeek_ad.synthetic_eval import NS, as_capture, evaluate_day, summarize  # noqa: E402
from zeek_ad.tgn_model import EventTGN, load_graph, score_capture, window_scores  # noqa: E402
from zeek_ad.transformer_model import WindowSequences, build_model, predict_scores  # noqa: E402
from zeek_ad.windows import PROJECT_CONFIG, load_window_config  # noqa: E402

SYN = PROJECT_ROOT / "outputs" / "synthetic" / "apt_v1"
SYN_CAPTURES = PROJECT_ROOT / "configs" / "synthetic" / "captures.syn1.v1.json"
SYN_CONFIG = PROJECT_ROOT / "configs" / "synthetic" / "apt-injection.v1.json"
EVAL = PROJECT_ROOT / "outputs" / "eval"
TRAIN_CAPTURE = "cic17-mon"
# 모델 → (Gold 버전, 원래 평가 run). 원래 run의 월요일 점수·임계값과 같은지 대조한다.
MODELS = {
    "tail_rarity": ("v1", "20261105T025744Z-tail_rarity"),
    "iforest": ("v1", "20261105T025744Z-iforest"),
    "transformer": ("v1", "20261106T034305Z-transformer"),
    "tail_rarity_v2": ("v2", "20261106T072530Z-tail_rarity_v2"),
    "iforest_v2": ("v2", "20261106T072530Z-iforest_v2"),
    "transformer_v2": ("v2", "20261106T072745Z-transformer_v2"),
    # TGN은 Gold 특징을 쓰지 않는다. 창 키와 split만 Gold v1에서 가져온다.
    "tgn_recon": ("v1", "20261110T104214Z-tgn_recon"),
    "tgn_shift": ("v1", "20261110T104214Z-tgn_shift"),
}
TGN_CONFIG = PROJECT_ROOT / "configs" / "models" / "tgn.v1.json"
TGN_COLUMNS = {"tgn_recon": "recon", "tgn_shift": "shift"}
TRANSFORMER_CONFIGS = {"transformer": "transformer.v1.json", "transformer_v2": "transformer.v2.json"}
CODE_FILES = [PROJECT_ROOT / "zeek_ad" / f for f in ["synthetic_eval.py", "evaluation.py", "baselines.py",
                                                     "sequences.py", "transformer_model.py", "tgn_model.py"]] + [Path(__file__).resolve()]


def load_gold(version):
    """월요일(원래 Gold) + 합성 네 날(합성 Gold)을 한 표로 합친다. 월요일은 원래 것을 그대로 쓴다."""
    orig_dir = PROJECT_ROOT / "outputs" / "gold" / f"conn_features_{version}"
    parts = []
    for d in [orig_dir, SYN / "gold" / f"conn_features_{version}"]:
        g = pd.read_parquet(d / "windows")
        g["capture_id"] = g["capture_id"].astype(str)
        parts.append(g[g.capture_id == TRAIN_CAPTURE] if d == orig_dir else g)
    # 월요일 행은 원래 읽은 순서를 지킨다. IF의 표본 추출이 train 행 순서에 따라 달라지기 때문이다.
    gold = pd.concat(parts, ignore_index=True)
    # v1 manifest에는 목록이 없다(gold_features.FEATURES).
    features = json.loads((orig_dir / "manifest.json").read_text(encoding="utf-8")).get("features", FEATURES)
    return gold, list(features)


def first_slots(window_seconds):
    slots = {}
    for path in [BOUNDS, SYN / "capture-bounds.json"]:
        for c in json.loads(path.read_text(encoding="utf-8"))["captures"]:
            slots[c["capture_id"]] = int(float(c["packet_time_min"]) // window_seconds * window_seconds)
    return slots


def transformer_scores(name, gold, features, run_dir):
    """원래 체크포인트로 점수를 매긴다. 시퀀스는 build_sequences.py와 같은 규칙으로 메모리에서 만든다."""
    config_path = PROJECT_ROOT / "configs" / "models" / TRANSFORMER_CONFIGS[name]
    config = json.loads(config_path.read_text(encoding="utf-8"))
    # build_sequences.py처럼 키 순서로 정렬한 표에 적합한다(표준화 값의 부동소수 합 순서까지 같게).
    order = gold.index
    gold = gold.sort_values(KEYS)
    train = gold[gold.split == "train"]
    pre = Preprocessor(features).fit(train)
    scaler = Scaler().fit(pre.transform(train)[features].to_numpy())
    z = scaler.transform(pre.transform(gold)[features].to_numpy())
    role = (gold["role"] == "responder").to_numpy(dtype=float)
    w = load_window_config(PROJECT_CONFIG)["window_seconds"]
    x, y = build_sequences(list(gold[KEYS].itertuples(index=False, name=None)), z, role, first_slots(w), w,
                           config["sequence"]["context_windows"])
    ckpt_path = next(run_dir.glob("*.pt"))
    ckpt = torch.load(ckpt_path, weights_only=True)
    model = build_model(config, n_in=x.shape[-1], n_out=y.shape[-1])
    model.load_state_dict(ckpt["state_dict"])
    loader = DataLoader(WindowSequences(x, y, np.ones(len(x), dtype=bool)), batch_size=512, shuffle=False)
    scores = pd.Series(predict_scores(model, loader, torch.device("cpu")).astype(float), index=gold.index)
    return scores.reindex(order).to_numpy(), [file_record(config_path), file_record(ckpt_path)]


def tgn_window_scores(run_dir, cache={}):
    """원래 run의 parameter로 합성 그래프(월요일 원래 이벤트 + 합성 네 날)를 흘려 창 점수를 만든다.

    합성 그래프는 새 외부 IP 8개 때문에 노드 수가 다르다. parameter는 노드 수와 무관하고,
    메모리·이웃 표는 캡처마다 0에서 시작하므로 그대로 쓴다. recon·shift가 한 번의 흐름에서 나온다.
    """
    if run_dir not in cache:
        config = json.loads(TGN_CONFIG.read_text(encoding="utf-8"))
        data, node_x, index, encoding = load_graph(SYN / "graphs" / "tgn_v1")
        tgn = EventTGN(config, encoding, num_nodes=node_x.shape[0], node_dim=node_x.shape[1],
                       raw_msg_dim=data.msg.shape[1])
        ckpt_path = next(run_dir.glob("*.pt"))
        tgn.load_parameter_state(torch.load(ckpt_path, weights_only=True)["parameters"])
        n = len(index)
        recon, shift_src, shift_dst = np.empty(n, np.float32), np.empty(n, np.float32), np.empty(n, np.float32)
        for cap in index.capture_id.unique():
            pos = np.flatnonzero((index.capture_id == cap).to_numpy())
            start, end = int(pos[0]), int(pos[-1]) + 1
            recon[start:end], shift_src[start:end], shift_dst[start:end] = score_capture(
                tgn, data, node_x, start, end, config["training"]["batch_events"])
        cache[run_dir] = (window_scores(index, recon, shift_src, shift_dst),
                          [file_record(TGN_CONFIG), file_record(ckpt_path),
                           file_record(SYN / "graphs" / "tgn_v1" / "manifest.json")])
    return cache[run_dir]


def score_model(name, gold, features, run_dir):
    if name.startswith("transformer"):
        return transformer_scores(name, gold, features, run_dir)
    if name.startswith("tgn"):
        win, files = tgn_window_scores(EVAL / MODELS["tgn_recon"][1])
        merged = gold[KEYS].merge(win[KEYS + [TGN_COLUMNS[name]]], on=KEYS, how="left", validate="one_to_one")
        if merged[TGN_COLUMNS[name]].isna().any() or len(win) != len(gold):
            sys.exit(f"{name}: Gold 행과 TGN 창이 일대일로 맞지 않는다")
        return merged[TGN_COLUMNS[name]].to_numpy(dtype=float), files
    train = gold[gold.split == "train"]
    if name.startswith("tail_rarity"):
        return TailRarity(features).fit(train).score(gold), []
    pre = Preprocessor(features).fit(train)
    return IForest().fit(pre.transform(train)).score(pre.transform(gold)), []


def reproduction(gold, scores, threshold, run_dir):
    """월요일 점수와 임계값이 원래 run과 같은지 본다. 같아야 '다시 학습하지 않은 같은 모델'이다."""
    ref = pd.read_parquet(run_dir / "scores.parquet")
    ref["capture_id"] = ref["capture_id"].astype(str)
    mon = gold[KEYS].assign(score=scores)
    mon = mon[mon.capture_id == TRAIN_CAPTURE].merge(ref[KEYS + ["score"]], on=KEYS, how="left",
                                                     suffixes=("", "_ref"), validate="one_to_one")
    ref_threshold = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))["threshold"]
    return {"monday_windows": len(mon), "monday_missing": int(mon.score_ref.isna().sum()),
            "monday_max_abs_diff": float(np.abs(mon.score - mon.score_ref).max()),
            "threshold": threshold, "reference_threshold": ref_threshold,
            "threshold_equal": bool(np.isclose(threshold, ref_threshold, rtol=0, atol=1e-9))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", nargs="+", default=list(MODELS), choices=list(MODELS))
    parser.add_argument("--out", type=Path, default=EVAL)
    args = parser.parse_args()

    syn_caps = json.loads(SYN_CAPTURES.read_text(encoding="utf-8"))["captures"]
    source_of = {c["capture_id"]: c["source_capture"] for c in syn_caps}
    capture_sha = {c["capture_id"]: c["pcap_sha256"]
                   for c in json.loads((SYN / "capture-bounds.json").read_text(encoding="utf-8"))["captures"]}
    syn_episodes = json.loads((SYN / "truth" / "episodes.json").read_text(encoding="utf-8"))["episodes"]
    syn_ids = {e["episode_id"] for e in syn_episodes if e["status"] == "confirmed"}
    pattern_of = {e["episode_id"]: e["pattern"] for e in syn_episodes}
    syn_truth = pd.read_parquet(SYN / "truth" / "windows.parquet")
    cic_truth = pd.read_parquet(TRUTH / "windows")
    cic_confirmed = {e["episode_id"] for e in json.loads(EPISODES.read_text(encoding="utf-8"))["episodes"]
                     if e["status"] == "confirmed"}

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = args.out / f"{stamp}-synthetic_apt_v1"
    out_dir.mkdir(parents=True)
    golds = {}
    results = {}
    setup_mlflow()
    for name in args.models:
        version, ref_run = MODELS[name]
        if version not in golds:
            golds[version] = load_gold(version)
        gold, features = golds[version]
        run_dir = EVAL / ref_run
        scores, model_files = score_model(name, gold, features, run_dir)
        threshold = holdout_threshold(gold, scores)
        repro = reproduction(gold, scores, threshold, run_dir)
        if repro["monday_missing"] or repro["monday_max_abs_diff"] > 1e-6 or not repro["threshold_equal"]:
            sys.exit(f"{name}: 원래 run과 월요일 점수·임계값이 다르다 {repro}")

        scored = gold.assign(score=scores)
        days = {}
        for cap, src in source_of.items():
            day = scored[(scored.capture_id == cap) & (scored.split != "capture_edge")]
            days[cap] = evaluate_day(
                day[KEYS + ["score"]].to_dict("records"), threshold, capture_sha,
                syn_truth[syn_truth.capture_id == cap].to_dict("records"), syn_ids,
                as_capture(cic_truth[cic_truth.capture_id == src].to_dict("records"), cap), cic_confirmed)
        summary = summarize(days, pattern_of)
        results[name] = {"threshold": threshold, "reproduction": repro, "summary": summary, "days": days}
        scored[scored.capture_id != TRAIN_CAPTURE][KEYS + ["split", "score"]].to_parquet(
            out_dir / f"scores_{name}.parquet", index=False)

        with mlflow.start_run(run_name=f"synthetic-{name}-{stamp}"):
            mlflow.set_tags({"stage": "3-synthetic", "model": name, "synthetic_config": "synthetic-apt.v1",
                             "reference_run": ref_run})
            mlflow.log_params({"threshold": threshold, "threshold_rule": "holdout p95 (cic17-mon)",
                               "gold_version": version, "retrained": "false"})
            for queue in ["main", "all"]:
                for n in NS:
                    m = summary[queue][n]
                    mlflow.log_metric(f"synthetic.{queue}.recall_at_{n}", m["matched"] / m["episodes"])
            mlflow.log_dict({"synthetic_manifest": file_record(SYN / "manifest.json"),
                             "synthetic_config": file_record(SYN_CONFIG),
                             "gold_manifests": [file_record(PROJECT_ROOT / "outputs" / "gold" / f"conn_features_{version}" / "manifest.json"),
                                                file_record(SYN / "gold" / f"conn_features_{version}" / "manifest.json")],
                             "model_files": model_files, "code": [file_record(p) for p in CODE_FILES]}, "lineage.json")
            mlflow.log_dict(results[name], "synthetic_metrics.json")

        m10, a10 = summary["main"][10], summary["all"][10]
        print(f"{name:15s} thr={threshold:.4f} main@10={m10['matched']}/{m10['episodes']} "
              f"[{m10['ci']['low']:.2f}, {m10['ci']['high']:.2f}] all@10={a10['matched']}/{a10['episodes']} "
              f"main@50={summary['main'][50]['matched']}")

    payload = {"synthetic_config": file_record(SYN_CONFIG), "tie_key_version": TIE_KEY_VERSION,
               "rule": "docs/design-decisions/DD-008-synthetic-apt-injection.md", "models": results}
    (out_dir / "metrics.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
                                          encoding="utf-8")
    print(f"-> {project_path(out_dir)}")


if __name__ == "__main__":
    main()
