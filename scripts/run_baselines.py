"""통계 기준선과 Isolation Forest를 월요일 학습 창으로 적합하고, 화~금을 사건 Recall@N으로 평가한다.

결과는 outputs/eval/<run>/와 MLflow(outputs/mlflow)에 남긴다.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import mlflow
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.baselines import IForest, Preprocessor, TailRarity  # noqa: E402
from zeek_ad.evaluation import TIE_KEY_VERSION  # noqa: E402
from zeek_ad.experiment import (  # noqa: E402
    EPISODES, GOLD, TRUTH, evaluate, holdout_threshold, load_eval_inputs, log_eval_metrics, print_result,
    setup_mlflow, summary_at_10, THRESHOLD_PERCENTILE,
)
from zeek_ad.gold_features import FEATURES  # noqa: E402
from zeek_ad.provenance import file_record  # noqa: E402

NAT = PROJECT_ROOT / "outputs" / "diagnostics" / "nat_v1"
CODE_FILES = [PROJECT_ROOT / "zeek_ad" / f for f in ["baselines.py", "evaluation.py", "experiment.py",
                                                     "gold_features.py"]] + [Path(__file__).resolve()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "eval")
    parser.add_argument("--models", nargs="+", default=["tail_rarity", "iforest", "nat_presence", "nat_count"])
    parser.add_argument("--gold", type=Path, default=GOLD, help="v2: outputs/gold/conn_features_v2")
    args = parser.parse_args()

    gold, truth, episodes, capture_sha = load_eval_inputs(args.gold)
    gold_manifest = json.loads((args.gold / "manifest.json").read_text(encoding="utf-8"))
    feature_version = gold_manifest["feature_version"]
    features = gold_manifest.get("features", FEATURES)  # v1 manifest에는 목록이 없다(gold_features.FEATURES)
    # v1이 아니면 모델 이름에 버전을 붙여 v1 결과와 나란히 둔다(예: iforest_v2).
    suffix = "" if feature_version == "conn-features.v1" else "_" + feature_version.rsplit(".", 1)[1]

    train = gold[gold.split == "train"]
    holdout = gold[gold.split == "holdout"]
    pre = Preprocessor(features).fit(train)
    tail = TailRarity(features).fit(train)
    forest = IForest().fit(pre.transform(train))
    # (점수, 설정, 임계값 규칙). None이면 보류 구간 p95를 쓴다.
    models = {
        "tail_rarity": (tail.score(gold), {"features": "pooled roles, raw values"}, None),
        "iforest": (forest.score(pre.transform(gold)), {**forest.params(), "preprocess": "log1p+median"}, None),
    }
    if NAT.exists():
        # NAT 편향 진단(배포 제외). 월요일에는 NAT 연결이 거의 없어 보류 p95가 0이 되고,
        # 그러면 모든 창이 후보가 된다. 그래서 후보 규칙을 "NAT 연결이 하나라도 있음"(점수 >= 1)으로 둔다.
        nat = pd.read_parquet(NAT / "windows")
        nat["capture_id"] = nat["capture_id"].astype(str)
        count = gold.merge(nat, on=["capture_id", "asset_id", "role", "window_start"], how="left")[
            "nat_conn_count"].fillna(0).to_numpy()
        models["nat_presence"] = ((count > 0).astype(float), {"score": "NAT 연결 유무(0/1)", "deployable": False}, 1.0)
        models["nat_count"] = (count, {"score": "NAT 연결 수", "deployable": False}, 1.0)
    models = {k + suffix: v for k, v in models.items() if k in args.models}

    setup_mlflow()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    summary = {}
    for name, (scores, params, fixed_threshold) in models.items():
        if fixed_threshold is None:
            threshold = holdout_threshold(gold, scores)
            rule = f"holdout p{THRESHOLD_PERCENTILE}"
        else:
            threshold, rule = fixed_threshold, f"fixed >= {fixed_threshold}"
        result = evaluate(gold, scores, threshold, truth, episodes, capture_sha)
        run_dir = args.out / f"{stamp}-{name}"
        run_dir.mkdir(parents=True)
        payload = {"model": name, "feature_version": feature_version, "threshold": threshold, "threshold_rule": rule,
                   "train_windows": len(train), "holdout_windows": len(holdout), "params": params,
                   "tie_key_version": TIE_KEY_VERSION, "days": result}
        (run_dir / "metrics.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str)
                                              + "\n", encoding="utf-8")
        gold[["capture_id", "asset_id", "role", "window_start", "split"]].assign(score=scores).to_parquet(
            run_dir / "scores.parquet", index=False)
        (run_dir / "preprocess.json").write_text(json.dumps(pre.params(), indent=2) + "\n", encoding="utf-8")

        with mlflow.start_run(run_name=f"{name}-{stamp}"):
            mlflow.set_tags({"stage": "3a" if not suffix else "3d", "model": name, "feature_version": feature_version})
            mlflow.log_params({"threshold": threshold, "threshold_rule": rule,
                               "train_windows": len(train), **{k: str(v) for k, v in params.items()}})
            # 입력·코드는 파일을 복사하지 않고 해시로 연결한다(설계 8절).
            mlflow.log_dict({"gold_manifest": file_record(args.gold / "manifest.json"),
                             "truth_manifest": file_record(TRUTH / "manifest.json"),
                             "episodes": file_record(EPISODES),
                             "code": [file_record(p) for p in CODE_FILES]}, "lineage.json")
            log_eval_metrics(result)
            mlflow.log_artifacts(str(run_dir))

        summary[name] = summary_at_10(threshold, result)
        print_result(name, threshold, run_dir, result)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
