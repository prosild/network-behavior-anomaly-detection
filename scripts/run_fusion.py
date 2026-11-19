"""ML·DL 결합 평가(DD-009): 세 모델의 하루 큐를 순위대로 번갈아 합쳐 CIC와 합성 APT를 평가한다.

설정: configs/models/fusion.v1.json. 모델 점수는 이미 끝난 run의 scores를 그대로 쓴다(다시 학습·채점하지 않음).
- CIC: confirmed 16건, 하루 큐. 모델 단독 결과가 원래 run과 같은지 먼저 확인한다.
- 합성: 합성 20건. 주 큐는 모델별 큐에서 CIC 사건을 뺀 뒤 합친다. 보조는 빼지 않고 합친다.
결과는 outputs/eval/<stamp>-fusion_v1/와 MLflow(실험 zeek-ad-stage3)에 남긴다.
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
from zeek_ad.evaluation import bootstrap_recall_ci, build_incidents, episode_edges, rank_queue  # noqa: E402
from zeek_ad.experiment import BOUNDS, EPISODES, EVAL_CAPTURES, TRUTH, setup_mlflow  # noqa: E402
from zeek_ad.fusion import fuse_round_robin  # noqa: E402
from zeek_ad.gold_features import KEYS  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402
from zeek_ad.synthetic_eval import NS, queue_result, summarize  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "models" / "fusion.v1.json"
EVAL = PROJECT_ROOT / "outputs" / "eval"
SYN = PROJECT_ROOT / "outputs" / "synthetic" / "apt_v1"
CODE_FILES = [PROJECT_ROOT / "zeek_ad" / f for f in ["fusion.py", "evaluation.py", "synthetic_eval.py"]] + [
    Path(__file__).resolve()]


def read_scores(path):
    s = pd.read_parquet(path)
    s["capture_id"] = s["capture_id"].astype(str)
    return s


def day_queue(scores, cap, threshold, capture_sha):
    # 기존 규약: 캡처 양끝 창 제외, 임계값 이상 창을 사건으로 묶고 점수·고정 해시 순서로 정렬.
    day = scores[(scores.capture_id == cap) & (scores.split != "capture_edge")]
    return rank_queue(build_incidents(day[KEYS + ["score"]].to_dict("records"), threshold, capture_sha))


def pooled(days, key, n):
    hits = {}
    for r in days.values():
        matched = set(r[key]["recall"][n]["matching"])
        for ep in r["denominator"]:
            hits[ep] = int(ep in matched)
    return {"matched": sum(hits.values()), "episodes": len(hits), "ci": bootstrap_recall_ci(hits.values())}


def cic_eval(models, names):
    truth = read_scores(TRUTH / "windows")
    episodes = json.loads(EPISODES.read_text(encoding="utf-8"))["episodes"]
    confirmed = {e["episode_id"] for e in episodes if e["status"] == "confirmed"}
    capture_sha = {c["capture_id"]: c["pcap_sha256"] for c in json.loads(BOUNDS.read_text(encoding="utf-8"))["captures"]}
    days = {}
    for cap in EVAL_CAPTURES:
        day_truth = truth[truth.capture_id == cap].to_dict("records")
        denominator = {t["episode_id"] for t in day_truth} & confirmed
        queues = [day_queue(m["scores"], cap, m["threshold"], capture_sha) for m in models]
        fused, sources = fuse_round_robin(queues, names)
        r = {"denominator": sorted(denominator)}
        for name, q in [("fusion", fused), *zip(names, queues)]:
            r[name] = queue_result(q, episode_edges(q, day_truth, confirmed), denominator)
        r["fusion_sources_top10"] = [sources[i.incident_id] for i in fused[:10]]
        days[cap] = r
    # 모델 단독 결과가 원래 run의 metrics와 같아야 같은 큐를 합친 것이다.
    for m, name in zip(models, names):
        for cap in EVAL_CAPTURES:
            for n in NS:
                ref = m["metrics"]["days"][cap]["recall"][str(n)]["matched"]
                if days[cap][name]["recall"][n]["matched"] != ref:
                    sys.exit(f"{name} {cap} @{n}: 단독 결과 {days[cap][name]['recall'][n]['matched']} != 원래 run {ref}")
    return days


def synthetic_eval(models, names):
    syn_caps = json.loads((PROJECT_ROOT / "configs" / "synthetic" / "captures.syn1.v1.json").read_text(encoding="utf-8"))["captures"]
    capture_sha = {c["capture_id"]: c["pcap_sha256"]
                   for c in json.loads((SYN / "capture-bounds.json").read_text(encoding="utf-8"))["captures"]}
    syn_episodes = json.loads((SYN / "truth" / "episodes.json").read_text(encoding="utf-8"))["episodes"]
    syn_ids = {e["episode_id"] for e in syn_episodes if e["status"] == "confirmed"}
    pattern_of = {e["episode_id"]: e["pattern"] for e in syn_episodes}
    syn_truth = read_scores(SYN / "truth" / "windows.parquet")
    cic_truth = read_scores(TRUTH / "windows")
    cic_confirmed = {e["episode_id"] for e in json.loads(EPISODES.read_text(encoding="utf-8"))["episodes"]
                     if e["status"] == "confirmed"}
    days = {}
    for c in syn_caps:
        cap, src = c["capture_id"], c["source_capture"]
        day_truth = syn_truth[syn_truth.capture_id == cap].to_dict("records")
        denominator = {t["episode_id"] for t in day_truth} & syn_ids
        cic = [{**t, "capture_id": cap} for t in cic_truth[cic_truth.capture_id == src].to_dict("records")]
        all_q = [day_queue(m["syn_scores"], cap, m["threshold"], capture_sha) for m in models]
        main_q = []
        for q in all_q:
            cic_edges = episode_edges(q, cic, cic_confirmed)
            main_q.append([i for i in q if not cic_edges[i.incident_id]])
        r = {"denominator": sorted(denominator)}
        for key, qs in [("main", main_q), ("all", all_q)]:
            fused, _ = fuse_round_robin(qs, names)
            r[key] = queue_result(fused, episode_edges(fused, day_truth, syn_ids), denominator)
            for name, q in zip(names, qs):
                r[f"{key}.{name}"] = queue_result(q, episode_edges(q, day_truth, syn_ids), denominator)
        # 패턴 표의 candidate: 세 모델 중 하나라도 후보를 만들었는가.
        r["diagnosis"] = {ep: {"candidate": any(r[f"all.{n}"]["best_rank"][ep] is not None for n in names)}
                          for ep in sorted(denominator)}
        days[cap] = r
    # 모델 단독 주 큐 결과가 합성 평가 run과 같아야 한다.
    for m, name in zip(models, names):
        ref_days = m["syn_metrics"]["days"]
        for cap in days:
            for n in NS:
                ref = ref_days[cap]["main"]["recall"][str(n)]["matched"]
                if days[cap][f"main.{name}"]["recall"][n]["matched"] != ref:
                    sys.exit(f"{name} {cap} 합성 @{n}: 단독 결과가 원래 run과 다르다")
    return days, summarize(days, pattern_of)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=EVAL)
    args = parser.parse_args()
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    names = [m["name"] for m in config["models"]]
    models = []
    for m in config["models"]:
        metrics = json.loads((EVAL / m["cic_run"] / "metrics.json").read_text(encoding="utf-8"))
        syn_path = EVAL / m["synthetic_scores"]
        syn_metrics = json.loads((syn_path.parent / "metrics.json").read_text(encoding="utf-8"))["models"][m["name"]]
        if syn_metrics["threshold"] != metrics["threshold"]:
            sys.exit(f"{m['name']}: 합성 run과 CIC run의 임계값이 다르다")
        models.append({"scores": read_scores(EVAL / m["cic_run"] / "scores.parquet"), "threshold": metrics["threshold"],
                       "metrics": metrics, "syn_scores": read_scores(syn_path), "syn_metrics": syn_metrics})

    cic_days = cic_eval(models, names)
    syn_days, syn_summary = synthetic_eval(models, names)
    cic_pooled = {key: {n: pooled(cic_days, key, n) for n in NS} for key in ["fusion", *names]}
    syn_pooled = {key: {n: pooled(syn_days, key, n) for n in NS} for key in ["main", "all", *[f"main.{n}" for n in names]]}

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.out / f"{stamp}-fusion_v1"
    run_dir.mkdir(parents=True)
    payload = {"config": file_record(CONFIG), "models": names, "cic_pooled": cic_pooled, "synthetic_pooled": syn_pooled,
               "synthetic_patterns": syn_summary["patterns"], "cic_days": cic_days, "synthetic_days": syn_days}
    (run_dir / "metrics.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
                                          encoding="utf-8")
    setup_mlflow()
    with mlflow.start_run(run_name=f"fusion_v1-{stamp}"):
        mlflow.set_tags({"stage": "3-fusion", "model": "fusion_v1", "config_id": config["config_id"]})
        mlflow.log_params({"models": ",".join(names), "rule": "round-robin by rank"})
        for n in NS:
            mlflow.log_metric(f"cic.pooled.recall_at_{n}", cic_pooled["fusion"][n]["matched"] / 16)
            mlflow.log_metric(f"synthetic.main.recall_at_{n}", syn_pooled["main"][n]["matched"] / 20)
            mlflow.log_metric(f"synthetic.all.recall_at_{n}", syn_pooled["all"][n]["matched"] / 20)
        mlflow.log_dict({"config": file_record(CONFIG),
                         "inputs": [file_record(EVAL / m["cic_run"] / "scores.parquet") for m in config["models"]]
                         + [file_record(EVAL / m["synthetic_scores"]) for m in config["models"]],
                         "code": [file_record(p) for p in CODE_FILES]}, "lineage.json")
        mlflow.log_artifact(str(run_dir / "metrics.json"))
        mlflow.log_artifact(str(CONFIG))

    for key, label in [("fusion", "결합"), *[(n, n) for n in names]]:
        p = cic_pooled[key]
        print(f"CIC {label:15s} " + "  ".join(f"@{n}={p[n]['matched']}/16" for n in NS)
              + f"  @10 CI [{p[10]['ci']['low']:.2f}, {p[10]['ci']['high']:.2f}]")
    for key in ["main", "all", *[f"main.{n}" for n in names]]:
        p = syn_pooled[key]
        print(f"합성 {key:20s} " + "  ".join(f"@{n}={p[n]['matched']}/20" for n in NS)
              + f"  @10 CI [{p[10]['ci']['low']:.2f}, {p[10]['ci']['high']:.2f}]")
    print(f"-> {project_path(run_dir)}")


if __name__ == "__main__":
    main()
