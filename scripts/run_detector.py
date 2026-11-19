"""고정 설정 파일 하나로 행동 탐지기 점수를 기존 평가 규약으로 평가한다(DD-006).

점수는 미리 만든 창 점수 표(설정의 scores_dir)를 읽는다. 결과는 outputs/eval/<run>-<detector>/와
MLflow(실험 zeek-ad-stage3, stage 3c)에 남긴다. 사건 단위 bootstrap 신뢰구간도 함께 저장한다.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
import mlflow  # noqa: E402
import pandas as pd  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.evaluation import TIE_KEY_VERSION, bootstrap_recall_ci, percentile, pooled_hits  # noqa: E402
from zeek_ad.experiment import (  # noqa: E402
    EPISODES, GOLD, NS, TRUTH, evaluate, load_eval_inputs, log_eval_metrics, print_result, setup_mlflow,
    summary_at_10,
)
from zeek_ad.gold_features import KEYS  # noqa: E402
from zeek_ad.provenance import file_record, sha256  # noqa: E402

CODE_FILES = [PROJECT_ROOT / "zeek_ad" / f for f in ["evaluation.py", "experiment.py"]] + [Path(__file__).resolve()]


def load_scores(config, config_path, gold):
    """설정에 맞게 만든 점수인지 해시로 확인하고, Gold 창 순서에 맞춘 점수 배열을 돌려준다."""
    scores_dir = PROJECT_ROOT / config["scores_dir"]
    manifest = json.loads((scores_dir / "manifest.json").read_text(encoding="utf-8"))
    problems = []
    if manifest["config"]["sha256"] != sha256(config_path):
        problems.append("점수를 만든 뒤 설정 파일이 바뀌었다")
    if manifest["gold_manifest"]["sha256"] != sha256(GOLD / "manifest.json"):
        problems.append("점수를 만든 뒤 Gold가 바뀌었다")
    if problems:
        sys.exit("입력 확인 실패: " + "; ".join(problems))
    table = pd.read_parquet(scores_dir / "windows")
    table["capture_id"] = table["capture_id"].astype(str)
    col = config["score_column"]
    merged = gold[KEYS].merge(table[KEYS + [col]], on=KEYS, how="left")
    if len(merged) != len(gold):
        sys.exit("점수 표에 같은 창이 두 번 있다")
    return merged[col].fillna(config["missing_window_score"]).astype(float).to_numpy(), manifest


def threshold_from_rule(rule, gold, scores):
    if rule["type"] == "holdout_percentile":
        t = percentile(list(scores[gold.split == "holdout"]), rule["percentile"])
        return max(t, rule.get("minimum", float("-inf"))), f"max(holdout p{rule['percentile']}, {rule.get('minimum')})"
    if rule["type"] == "fixed":
        return float(rule["value"]), f"fixed >= {rule['value']}"
    raise ValueError(f"모르는 임계값 규칙: {rule['type']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, help="configs/detectors/*.json")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "eval")
    args = parser.parse_args()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    name = config["detector"]

    gold, truth, episodes, capture_sha = load_eval_inputs()
    scores, score_manifest = load_scores(config, config_path, gold)
    threshold, rule = threshold_from_rule(config["threshold_rule"], gold, scores)
    # 갱신 규칙이 임계값을 쓰는 탐지기는 점수를 만들 때 쓴 임계값과 같아야 한다.
    if "update_threshold" in score_manifest and score_manifest["update_threshold"] != threshold:
        sys.exit(f"임계값 불일치: 점수 생성 {score_manifest['update_threshold']} vs 평가 {threshold}")
    result = evaluate(gold, scores, threshold, truth, episodes, capture_sha)
    ci = {n: bootstrap_recall_ci(pooled_hits(result, n).values()) for n in NS}

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.out / f"{stamp}-{name}"
    run_dir.mkdir(parents=True)
    lineage = {"config": file_record(config_path), "score_manifest": file_record(PROJECT_ROOT / config["scores_dir"] / "manifest.json"),
               "score_code": score_manifest["code"], "gold_manifest": file_record(GOLD / "manifest.json"),
               "truth_manifest": file_record(TRUTH / "manifest.json"), "episodes": file_record(EPISODES),
               "code": [file_record(p) for p in CODE_FILES]}
    payload = {"model": name, "config_id": config["config_id"], "threshold": threshold, "threshold_rule": rule,
               "deployable": config.get("deployable"), "exposure": "결과 노출 이후 설계 변경(DD-006)",
               "tie_key_version": TIE_KEY_VERSION, "pooled_ci": ci, "lineage": lineage, "days": result}
    (run_dir / "metrics.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
                                          encoding="utf-8")
    gold[KEYS + ["split"]].assign(score=scores).to_parquet(run_dir / "scores.parquet", index=False)

    setup_mlflow()
    with mlflow.start_run(run_name=f"{name}-{stamp}"):
        mlflow.set_tags({"stage": "3c", "model": name, "config_id": config["config_id"],
                         "exposure": "post-result design change (DD-006)"})
        mlflow.log_params({"threshold": threshold, "threshold_rule": rule})
        mlflow.log_dict(lineage, "lineage.json")
        log_eval_metrics(result)
        for n, c in ci.items():
            mlflow.log_metrics({f"pooled.recall_at_{n}": c["recall"], f"pooled.recall_at_{n}.ci_low": c["low"],
                                f"pooled.recall_at_{n}.ci_high": c["high"]})
        mlflow.log_artifacts(str(run_dir))

    print_result(name, threshold, run_dir, result)
    print(json.dumps({**summary_at_10(threshold, result),
                      "pooled@10": f"{ci[10]['recall']:.3f} [{ci[10]['low']:.3f}, {ci[10]['high']:.3f}]"},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
