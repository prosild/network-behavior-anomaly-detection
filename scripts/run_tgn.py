"""TGN 이벤트 그래프 모델을 고정 설정으로 학습하고, 기존 평가기로 화~금을 평가한다(DD-007).

설정: configs/models/tgn.v1.json. 입력: outputs/graphs/tgn_v1/.
1. 월요일 train 이벤트로 10 epoch 학습(CPU, seed 42).
2. 캡처(하루)마다 메모리·이웃 표를 비우고 시간순으로 흘려 연결 점수를 매긴다(점수 먼저, 갱신 나중).
3. 창 최댓값으로 모아 recon·shift를 따로 평가한다(보류 p95, 사건, Recall@N).
4. 진단: NAT(172.16.0.1) 연결을 뺀 점수, 공격 구간의 창별 점수 변화.
결과는 outputs/eval/<stamp>-tgn_recon/, <stamp>-tgn_shift/와 MLflow(실험 zeek-ad-stage3, 단계 3c)에 남긴다.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
import mlflow  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import torch  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.evaluation import TIE_KEY_VERSION, bootstrap_recall_ci, pooled_hits  # noqa: E402
from zeek_ad.experiment import (  # noqa: E402
    EPISODES, GOLD, TRUTH, evaluate, holdout_threshold, load_eval_inputs, log_eval_metrics, print_result,
    setup_mlflow, summary_at_10, THRESHOLD_PERCENTILE,
)
from zeek_ad.provenance import file_record, sha256  # noqa: E402
from zeek_ad.tgn_model import EventTGN, KEYS, load_graph, score_capture, train_epoch, window_scores  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "models" / "tgn.v1.json"
GRAPH = PROJECT_ROOT / "outputs" / "graphs" / "tgn_v1"
NAT = "172.16.0.1"
TRAIN_CAPTURE = "cic17-mon"
CODE_FILES = [PROJECT_ROOT / "zeek_ad" / f for f in ["tgn_model.py", "evaluation.py", "experiment.py"]] + [
    Path(__file__).resolve()]


def check_inputs(config, graph_dir, encoding):
    # 그래프 파일이 만들어진 그대로인지, 설정의 data 절과 인코딩이 맞는지 확인한다.
    # 설정 파일 해시는 그래프를 만든 뒤 model·training·score 절을 채워서 다르다(진행 기록 11번).
    manifest = json.loads((graph_dir / "manifest.json").read_text(encoding="utf-8"))
    problems = [f"그래프 파일 해시가 다르다: {o['path']}" for o in manifest["outputs"]
                if sha256(PROJECT_ROOT / o["path"]) != o["sha256"]]
    d = config["data"]
    if encoding["categorical"] != d["categorical"] or encoding["numeric"] != d["numeric_log1p"] + d["numeric_raw"]:
        problems.append("설정 data 절과 그래프 인코딩의 열 목록이 다르다")
    if problems:
        sys.exit("입력 확인 실패: " + "; ".join(problems))
    return manifest


def capture_ranges(index):
    """캡처마다 [시작, 끝) 위치. 그래프는 캡처 순서로 이어져 있어야 한다."""
    ranges = {}
    for cap in index.capture_id.unique():
        pos = np.flatnonzero((index.capture_id == cap).to_numpy())
        if pos[-1] - pos[0] + 1 != len(pos):
            sys.exit(f"{cap} 이벤트가 이어져 있지 않다")
        ranges[cap] = (int(pos[0]), int(pos[-1]) + 1)
    return ranges


def train(tgn, config, data, node_x, index):
    t = config["training"]
    pos = np.flatnonzero(((index.capture_id == TRAIN_CAPTURE) & (index.split == "train")).to_numpy())
    start, end = int(pos[0]), int(pos[-1]) + 1
    if end - start != len(pos):
        sys.exit("train 이벤트가 시간상 이어진 한 구간이 아니다")
    optimizer = torch.optim.Adam(tgn.parameters(), lr=t["learning_rate"])
    history, began = [], time.perf_counter()
    # epoch 수는 고정이다. 보류는 임계값용이라 epoch 선택에 쓰지 않는다.
    for epoch in range(t["epochs"]):
        loss = train_epoch(tgn, data, node_x, start, end, t["batch_events"], optimizer)
        history.append({"epoch": epoch, "train_loss": loss, "seconds": round(time.perf_counter() - began)})
        print(history[-1], flush=True)
    return history, len(pos)


def score_all(tgn, data, node_x, index, batch_size):
    """모든 캡처를 하루씩 흘려 이벤트 점수 배열 셋을 index 순서로 돌려준다."""
    n = len(index)
    recon, shift_src, shift_dst = np.empty(n, np.float32), np.empty(n, np.float32), np.empty(n, np.float32)
    seconds = {}
    for cap, (start, end) in capture_ranges(index).items():
        began = time.perf_counter()
        recon[start:end], shift_src[start:end], shift_dst[start:end] = score_capture(
            tgn, data, node_x, start, end, batch_size)
        seconds[cap] = round(time.perf_counter() - began)
        print(f"scored {cap} {end - start} events {seconds[cap]}s", flush=True)
    return recon, shift_src, shift_dst, seconds


def to_gold(gold, win, column, fill=None):
    """창 점수를 Gold 행 순서로 옮긴다. fill이 없으면 모든 Gold 행이 점수를 하나씩 받아야 한다."""
    merged = gold[KEYS].merge(win[KEYS + [column]], on=KEYS, how="left", validate="one_to_one")
    if fill is None:
        if merged[column].isna().any():
            sys.exit(f"Gold 행 {int(merged[column].isna().sum())}개가 TGN 창 점수를 받지 못했다")
    else:
        merged[column] = merged[column].fillna(fill)
    return merged[column].to_numpy(dtype=float)


def decay_diagnostic(gold, scores, truth, episodes):
    """공격 구간에서 창 점수가 시간이 갈수록 줄어드는지(메모리 갱신으로 익숙해지는지) 본다.

    confirmed 에피소드의 (자산, 역할) 계열마다 정답 창을 시간순으로 놓고, 처음 1/3과 마지막 1/3의 중앙값,
    순서와 점수의 Spearman 상관을 낸다. 창이 3개 미만인 계열은 뺀다.
    """
    confirmed = {e["episode_id"] for e in episodes if e["status"] == "confirmed"}
    keyed = gold[KEYS].assign(score=scores)
    t = truth[truth.episode_id.isin(confirmed)].merge(keyed, on=KEYS, how="inner")
    out = []
    for (ep, asset, role), g in t.groupby(["episode_id", "asset_id", "role"]):
        g = g.sort_values("window_start")
        k = len(g)
        if k < 3:
            continue
        third = max(k // 3, 1)
        first, last = float(g.score.iloc[:third].median()), float(g.score.iloc[-third:].median())
        out.append({"episode_id": ep, "asset_id": asset, "role": role, "windows": k,
                    "first_third_median": first, "last_third_median": last,
                    "last_over_first": last / first if first else None,
                    "spearman_order_score": float(pd.Series(range(k)).corr(g.score.reset_index(drop=True),
                                                                           method="spearman")),
                    "scores": [round(float(s), 4) for s in g.score]})
    ratios = [o["last_over_first"] for o in out if o["last_over_first"] is not None]
    return {"series": out, "series_count": len(out),
            "median_last_over_first": float(np.median(ratios)) if ratios else None,
            "series_dropping_by_half": sum(r < 0.5 for r in ratios)}


def pooled_summary(result, n):
    hits = pooled_hits(result, n)
    return {"matched": sum(hits.values()), "episodes": len(hits), "ci": bootstrap_recall_ci(hits.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "eval")
    args = parser.parse_args()

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    if config["training"]["device"] != "cpu":
        sys.exit("재현성을 위해 CPU만 쓴다")
    data, node_x, index, encoding = load_graph(GRAPH)
    graph_manifest = check_inputs(config, GRAPH, encoding)

    tgn = EventTGN(config, encoding, num_nodes=node_x.shape[0], node_dim=node_x.shape[1],
                   raw_msg_dim=data.msg.shape[1])
    n_params = sum(p.numel() for p in tgn.parameters())
    print(f"parameters {n_params:,}")
    history, n_train = train(tgn, config, data, node_x, index)
    recon, shift_src, shift_dst, score_seconds = score_all(tgn, data, node_x, index,
                                                           config["training"]["batch_events"])

    gold, truth, episodes, capture_sha = load_eval_inputs(GOLD)
    win = window_scores(index, recon, shift_src, shift_dst)
    if len(win) != len(gold):
        sys.exit(f"TGN 창 {len(win)}개와 Gold 창 {len(gold)}개의 수가 다르다")
    win_no_nat = window_scores(index, recon, shift_src, shift_dst, exclude_peer=NAT)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ckpt_name = f"{config['config_id'].replace('.', '_')}.pt"
    checkpoint = {"config_id": config["config_id"], "parameters": tgn.parameter_state(),
                  "graph_manifest_sha256": sha256(GRAPH / "manifest.json")}
    params = {**{f"model.{k}": v for k, v in config["model"].items() if not isinstance(v, (dict, str))},
              **{f"model.{k}.{kk}": vv for k, v in config["model"].items() if isinstance(v, dict)
                 for kk, vv in v.items() if not isinstance(vv, str)},
              **{f"training.{k}": config["training"][k] for k in ["batch_events", "epochs", "learning_rate", "seed"]},
              "parameters": n_params, "device": "cpu", "torch": torch.__version__}
    setup_mlflow()
    summary = {}
    for name, column, rule_note in [("tgn_recon", "recon", "이벤트 복원 손실의 창 최댓값"),
                                    ("tgn_shift", "shift", "메모리 이동량의 창 최댓값")]:
        scores = to_gold(gold, win, column)
        threshold = holdout_threshold(gold, scores)
        result = evaluate(gold, scores, threshold, truth, episodes, capture_sha)
        # NAT 제외 진단: 상대가 NAT인 연결을 뺀 창 최댓값. 연결이 모두 빠진 창은 0이다.
        nn_scores = to_gold(gold, win_no_nat, column, fill=0.0)
        nn_threshold = holdout_threshold(gold, nn_scores)
        nn_result = evaluate(gold, nn_scores, nn_threshold, truth, episodes, capture_sha)
        decay = decay_diagnostic(gold, scores, truth, episodes)

        run_dir = args.out / f"{stamp}-{name}"
        run_dir.mkdir(parents=True)
        pooled = {n: pooled_summary(result, n) for n in [10, 50]}
        payload = {"model": name, "score": rule_note, "config_id": config["config_id"], "threshold": threshold,
                   "threshold_rule": f"holdout p{THRESHOLD_PERCENTILE}", "train_events": n_train,
                   "holdout_windows": int((gold.split == "holdout").sum()), "params": params,
                   "tie_key_version": TIE_KEY_VERSION, "history": history, "score_seconds": score_seconds,
                   "pooled": pooled, "days": result}
        (run_dir / "metrics.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
                                              encoding="utf-8")
        (run_dir / "no_nat.json").write_text(json.dumps(
            {"rule": f"상대가 {NAT}인 연결을 뺀 창 최댓값(없으면 0), 임계값은 그 점수의 보류 p95",
             "threshold": nn_threshold, "pooled": {n: pooled_summary(nn_result, n) for n in [10, 50]},
             "days": nn_result}, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
        (run_dir / "decay.json").write_text(json.dumps(decay, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        gold[KEYS + ["split"]].assign(score=scores, score_no_nat=nn_scores).to_parquet(
            run_dir / "scores.parquet", index=False)
        torch.save(checkpoint, run_dir / ckpt_name)
        if name == "tgn_recon":
            # 이벤트 점수(합성 평가·결합 결정에서 다시 쓴다). 크기가 커서 MLflow에는 올리지 않는다.
            np.savez_compressed(run_dir / "event_scores.npz", recon=recon, shift_src=shift_src, shift_dst=shift_dst)

        with mlflow.start_run(run_name=f"{name}-{stamp}"):
            mlflow.set_tags({"stage": "3c", "model": name, "config_id": config["config_id"]})
            mlflow.log_params({"threshold": threshold, "threshold_rule": f"holdout p{THRESHOLD_PERCENTILE}",
                               "train_events": n_train, **{k: str(v) for k, v in params.items()}})
            for h in history:
                mlflow.log_metric("train_loss", h["train_loss"], step=h["epoch"])
            mlflow.log_dict({"graph_manifest": file_record(GRAPH / "manifest.json"),
                             "events_manifest": graph_manifest.get("events_manifest") or graph_manifest.get("events_manifests"),
                             "gold_manifest": file_record(GOLD / "manifest.json"),
                             "truth_manifest": file_record(TRUTH / "manifest.json"),
                             "episodes": file_record(EPISODES), "config": file_record(CONFIG),
                             "code": [file_record(p) for p in CODE_FILES]}, "lineage.json")
            log_eval_metrics(result)
            for n in [10, 50]:
                mlflow.log_metric(f"pooled.recall_at_{n}", pooled[n]["matched"] / pooled[n]["episodes"])
            for f in ["metrics.json", "no_nat.json", "decay.json", "scores.parquet", ckpt_name]:
                mlflow.log_artifact(str(run_dir / f))
            mlflow.log_artifact(str(CONFIG))

        summary[name] = {**summary_at_10(threshold, result),
                         "pooled@10": f"{pooled[10]['matched']}/{pooled[10]['episodes']}",
                         "pooled@50": f"{pooled[50]['matched']}/{pooled[50]['episodes']}",
                         "no_nat_threshold": round(nn_threshold, 4),
                         "no_nat@10": "{matched}/{episodes}".format(**pooled_summary(nn_result, 10)),
                         "decay_median_last_over_first": decay["median_last_over_first"]}
        print_result(name, threshold, run_dir, result)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
