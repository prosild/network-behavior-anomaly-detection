"""Transformer 비교 모델을 고정 설정으로 학습하고, 기준선과 같은 평가기로 화~금을 평가한다(DD-002).

설정: configs/models/transformer.v1.json. 입력: outputs/sequences/transformer_v1/.
결과는 outputs/eval/<run>-transformer/와 MLflow(실험 zeek-ad-stage3)에 남긴다.
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
import torch  # noqa: E402
from torch import nn  # noqa: E402
from torch.utils.data import DataLoader  # noqa: E402
import pandas as pd  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.evaluation import TIE_KEY_VERSION  # noqa: E402
from zeek_ad.experiment import (  # noqa: E402
    EPISODES, GOLD, TRUTH, evaluate, holdout_threshold, load_eval_inputs, log_eval_metrics, print_result,
    setup_mlflow, summary_at_10, THRESHOLD_PERCENTILE,
)
from zeek_ad.gold_features import KEYS  # noqa: E402
from zeek_ad.provenance import file_record, sha256  # noqa: E402
from zeek_ad.transformer_model import (  # noqa: E402
    WindowSequences, build_model, evaluate_loss, predict_scores, train_one_epoch,
)

CONFIG = PROJECT_ROOT / "configs" / "models" / "transformer.v1.json"
CODE_FILES = [PROJECT_ROOT / "zeek_ad" / f for f in ["transformer_model.py", "sequences.py", "evaluation.py",
                                                     "experiment.py"]] + [Path(__file__).resolve()]
# 재현성을 위해 CPU로 고정한다(GPU는 일부 연산 결과가 실행마다 미세하게 다를 수 있다).
DEVICE = torch.device("cpu")


def check_inputs(config_path, seq_manifest, gold_dir):
    # 시퀀스가 지금의 고정 설정과 Gold로 만들어졌는지 해시로 확인한다.
    problems = []
    if seq_manifest["config"]["sha256"] != sha256(config_path):
        problems.append("시퀀스를 만든 뒤 설정 파일이 바뀌었다")
    if seq_manifest["gold_manifest"]["sha256"] != sha256(gold_dir / "manifest.json"):
        problems.append("시퀀스를 만든 뒤 Gold가 바뀌었다")
    for o in seq_manifest["outputs"]:
        if sha256(PROJECT_ROOT / o["path"]) != o["sha256"]:
            problems.append(f"시퀀스 파일 해시가 다르다: {o['path']}")
    if problems:
        sys.exit("입력 확인 실패: " + "; ".join(problems))


def train(config, X, Y, index):
    t = config["training"]
    is_train = (index.split == "train").to_numpy()
    is_holdout = (index.split == "holdout").to_numpy()
    model = build_model(config, n_in=X.shape[-1], n_out=Y.shape[-1]).to(DEVICE)
    train_loader = DataLoader(WindowSequences(X, Y, is_train), batch_size=t["batch_size"], shuffle=True,
                              generator=torch.Generator().manual_seed(t["seed"]))
    holdout_loader = DataLoader(WindowSequences(X, Y, is_holdout), batch_size=512, shuffle=False)
    optimizer = torch.optim.Adam(model.parameters(), lr=t["learning_rate"])
    loss_fn = nn.MSELoss()
    history = []
    # epoch 수는 고정이다. 보류 loss는 기록만 하고 고르는 데 쓰지 않는다(보류는 임계값용).
    for epoch in range(t["epochs"]):
        tr = train_one_epoch(model, train_loader, optimizer, loss_fn, DEVICE)
        ho = evaluate_loss(model, holdout_loader, loss_fn, DEVICE)
        history.append({"epoch": epoch, "train_loss": tr, "holdout_loss": ho})
    return model, history, int(is_train.sum())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "eval")
    parser.add_argument("--config", type=Path, default=CONFIG)
    args = parser.parse_args()

    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    # v1 설정에는 inputs 절이 없다. 그때는 v1 경로·이름을 쓴다.
    inputs = config.get("inputs", {})
    gold_dir = PROJECT_ROOT / inputs.get("gold", "outputs/gold/conn_features_v1")
    seq_dir = PROJECT_ROOT / inputs.get("sequences", "outputs/sequences/transformer_v1")
    name = inputs.get("model_name", "transformer")
    feature_version = json.loads((gold_dir / "manifest.json").read_text(encoding="utf-8"))["feature_version"]
    seq_manifest = json.loads((seq_dir / "manifest.json").read_text(encoding="utf-8"))
    check_inputs(config_path, seq_manifest, gold_dir)
    d = np.load(seq_dir / "sequences.npz")
    X, Y = d["x"], d["y"]
    index = pd.read_parquet(seq_dir / "index.parquet")

    model, history, n_train = train(config, X, Y, index)
    all_loader = DataLoader(WindowSequences(X, Y, np.ones(len(X), dtype=bool)), batch_size=512, shuffle=False)
    seq_scores = index.assign(score=predict_scores(model, all_loader, DEVICE))

    # 시퀀스 순서의 점수를 Gold 행 순서로 옮긴다. 모든 Gold 행이 점수를 하나씩 받아야 한다.
    gold, truth, episodes, capture_sha = load_eval_inputs(gold_dir)
    merged = gold[KEYS].merge(seq_scores[KEYS + ["score"]], on=KEYS, how="left", validate="one_to_one")
    if len(merged) != len(gold) or merged.score.isna().any():
        sys.exit("Gold 행과 시퀀스 점수가 일대일로 맞지 않는다")
    scores = merged.score.to_numpy(dtype=float)  # float32 그대로면 임계값이 JSON에 문자열로 남는다
    threshold = holdout_threshold(gold, scores)
    rule = f"holdout p{THRESHOLD_PERCENTILE}"
    result = evaluate(gold, scores, threshold, truth, episodes, capture_sha)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.out / f"{stamp}-{name}"
    run_dir.mkdir(parents=True)
    params = {**{f"model.{k}": v for k, v in config["model"].items()},
              **{f"training.{k}": v for k, v in config["training"].items()},
              "sequence.context_windows": config["sequence"]["context_windows"],
              "parameters": sum(p.numel() for p in model.parameters()), "device": str(DEVICE),
              "torch": torch.__version__}
    payload = {"model": name, "feature_version": feature_version, "config_id": config["config_id"], "threshold": threshold,
               "threshold_rule": rule, "train_windows": n_train,
               "holdout_windows": int((gold.split == "holdout").sum()), "params": params,
               "tie_key_version": TIE_KEY_VERSION, "history": history, "days": result}
    (run_dir / "metrics.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
                                          encoding="utf-8")
    gold[KEYS + ["split"]].assign(score=scores).to_parquet(run_dir / "scores.parquet", index=False)
    # 체크포인트는 state_dict만 저장한다. 전처리 값은 시퀀스 manifest에 있다(배포 묶음은 단계 4).
    torch.save({"config_id": config["config_id"], "state_dict": model.state_dict(),
                "sequences_manifest_sha256": sha256(seq_dir / "manifest.json")},
               run_dir / f"{config['config_id'].replace('.', '_')}.pt")

    setup_mlflow()
    with mlflow.start_run(run_name=f"{name}-{stamp}"):
        mlflow.set_tags({"stage": "3b" if name == "transformer" else "3d", "model": name, "feature_version": feature_version,
                         "config_id": config["config_id"]})
        mlflow.log_params({"threshold": threshold, "threshold_rule": rule, "train_windows": n_train,
                           **{k: str(v) for k, v in params.items()}})
        for h in history:
            mlflow.log_metrics({"train_loss": h["train_loss"], "holdout_loss": h["holdout_loss"]}, step=h["epoch"])
        mlflow.log_dict({"gold_manifest": file_record(gold_dir / "manifest.json"),
                         "sequences_manifest": file_record(seq_dir / "manifest.json"),
                         "truth_manifest": file_record(TRUTH / "manifest.json"),
                         "episodes": file_record(EPISODES), "config": file_record(config_path),
                         "code": [file_record(p) for p in CODE_FILES]}, "lineage.json")
        log_eval_metrics(result)
        mlflow.log_artifacts(str(run_dir))
        mlflow.log_artifact(str(config_path))

    last = history[-1]
    best = min(history, key=lambda h: h["holdout_loss"])
    print(f"train_loss {history[0]['train_loss']:.4f} -> {last['train_loss']:.4f}, holdout_loss "
          f"{history[0]['holdout_loss']:.4f} -> min {best['holdout_loss']:.4f}@{best['epoch']} -> {last['holdout_loss']:.4f}")
    print_result(name, threshold, run_dir, result)
    print(json.dumps(summary_at_10(threshold, result), indent=2))


if __name__ == "__main__":
    main()
