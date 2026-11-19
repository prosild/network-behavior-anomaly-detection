"""단계 3 실험 공통 부분: 평가 입력 읽기, 하루별 평가, MLflow 설정·지표 기록.

scripts/run_baselines.py와 scripts/run_transformer.py가 같은 평가기를 쓰도록 한곳에 둔다.
"""

import json

import mlflow
import pandas as pd

from zeek_ad.db import mlflow_tracking_uri
from zeek_ad.evaluation import (
    build_incidents, episode_edges, per_episode_counts, percentile, rank_queue, recall_at_n,
    tie_sensitivity,
)
from zeek_ad.provenance import PROJECT_ROOT

GOLD = PROJECT_ROOT / "outputs" / "gold" / "conn_features_v1"
TRUTH = PROJECT_ROOT / "outputs" / "ground_truth" / "cic17_v1"
EPISODES = PROJECT_ROOT / "configs" / "ground-truth" / "cic17-episodes.v1.json"
BOUNDS = PROJECT_ROOT / "manifests" / "cic-ids-2017.capture-bounds.v1.json"
MLFLOW_DIR = PROJECT_ROOT / "outputs" / "mlflow"
EXPERIMENT = "zeek-ad-stage3"
EVAL_CAPTURES = ["cic17-tue", "cic17-wed", "cic17-thu", "cic17-fri"]
NS = [5, 10, 20, 50]
THRESHOLD_PERCENTILE = 95


def setup_mlflow():
    # 백엔드(run·지표·Registry)는 PostgreSQL mlflow DB, artifact는 로컬 폴더다(설계 7.1절).
    # 2026-11-11까지의 SQLite 기록(outputs/mlflow/mlflow.db)은 scripts/migrate_mlflow_to_pg.py로 옮겼다.
    MLFLOW_DIR.mkdir(parents=True, exist_ok=True)
    mlflow.set_tracking_uri(mlflow_tracking_uri())
    if mlflow.get_experiment_by_name(EXPERIMENT) is None:
        mlflow.create_experiment(EXPERIMENT, artifact_location=(MLFLOW_DIR / "artifacts").as_uri())
    mlflow.set_experiment(EXPERIMENT)


def load_eval_inputs(gold_dir=GOLD):
    """Gold 창, 정답 창, 에피소드 목록, 캡처별 pcap 해시(동점 키용)를 읽는다."""
    gold = pd.read_parquet(gold_dir / "windows")
    gold["capture_id"] = gold["capture_id"].astype(str)
    truth = pd.read_parquet(TRUTH / "windows")
    episodes = json.loads(EPISODES.read_text(encoding="utf-8"))["episodes"]
    capture_sha = {c["capture_id"]: c["pcap_sha256"]
                   for c in json.loads(BOUNDS.read_text(encoding="utf-8"))["captures"]}
    return gold, truth, episodes, capture_sha


def holdout_threshold(gold, scores):
    # 월요일 보류 점수의 95번째 백분위수(설계 5.2절).
    return percentile(list(scores[gold.split == "holdout"]), THRESHOLD_PERCENTILE)


def evaluate(gold, scores, threshold, truth, episodes, capture_sha):
    """캡처(하루)마다 조사 큐를 만들고 N별 Recall과 공격별 결과를 계산한다."""
    confirmed = {e["episode_id"] for e in episodes if e["status"] == "confirmed"}
    uncertain = {e["episode_id"] for e in episodes if e["status"] == "uncertain"}
    scored = gold.assign(score=scores)
    result = {}
    for cap in EVAL_CAPTURES:
        # 캡처 양끝의 불완전한 창은 주 비교에서 뺀다(설계 4.3절). 정답 분모에서는 지우지 않는다.
        day = scored[(scored.capture_id == cap) & (scored.split != "capture_edge")]
        incidents = build_incidents(day.to_dict("records"), threshold, capture_sha)
        queue = rank_queue(incidents)
        day_truth = truth[truth.capture_id == cap]
        denominator = set(day_truth.episode_id) & confirmed
        edges = episode_edges(queue, day_truth.to_dict("records"), confirmed)
        uncertain_edges = episode_edges(queue, day_truth.to_dict("records"), uncertain)
        edge_only = {ep for ep in denominator
                     if set(day_truth[day_truth.episode_id == ep].split) == {"capture_edge"}}
        # 미탐 원인 구분: 후보 생성 실패(임계값 미달)와 순위 손실(후보지만 상위 N 밖).
        keyed = day.set_index(["asset_id", "role", "window_start"]).score
        rank_of = {}
        for k, inc in enumerate(queue, 1):
            for ep in edges[inc.incident_id]:
                rank_of.setdefault(ep, k)
        diagnosis = {}
        for ep in sorted(denominator):
            keys = [tuple(x) for x in day_truth[day_truth.episode_id == ep][["asset_id", "role", "window_start"]]
                    .itertuples(index=False)]
            ep_scores = [keyed[k] for k in keys if k in keyed.index]
            # numpy 값은 JSON에 문자열("False")로 남으므로 파이썬 float·bool로 바꾼다.
            diagnosis[ep] = {"max_window_score": float(max(ep_scores)) if ep_scores else None,
                             "candidate": bool(ep_scores) and bool(max(ep_scores) >= threshold),
                             "best_rank": rank_of.get(ep)}
        result[cap] = {
            "diagnosis": diagnosis,
            "windows": len(day), "candidate_windows": int((day.score >= threshold).sum()),
            "incidents": len(queue), "denominator": sorted(denominator),
            "episodes_only_in_capture_edge": sorted(edge_only),
            "recall": {n: recall_at_n(queue, n, edges, denominator) for n in NS},
            "tie_sensitivity": {n: tie_sensitivity(queue, n, edges, denominator) for n in NS},
            "per_episode_at_10": per_episode_counts(queue, 10, edges, denominator),
            "uncertain_touched_at_10": sorted(set().union(
                *[uncertain_edges[i.incident_id] for i in queue[:10]] or [set()])),
            "top10": [{"rank": k + 1, "incident_id": i.incident_id, "score": i.score,
                       "windows": len(i.windows), "episodes": sorted(edges[i.incident_id])}
                      for k, i in enumerate(queue[:10])],
        }
    return result


def log_eval_metrics(result):
    # 하루·N별 Recall과 사건 수를 MLflow metric으로 남긴다.
    for cap, r in result.items():
        for n, m in r["recall"].items():
            mlflow.log_metric(f"{cap}.recall_at_{n}", m["recall"])
            mlflow.log_metric(f"{cap}.inclusive_recall_at_{n}", m["inclusive_recall"])
        mlflow.log_metric(f"{cap}.incidents", r["incidents"])


def print_result(name, threshold, run_dir, result):
    print(f"\n== {name}  threshold={threshold:.4f}  -> {run_dir.relative_to(PROJECT_ROOT)}")
    for cap, r in result.items():
        rec = "  ".join(f"@{n}={r['recall'][n]['matched']}/{len(r['denominator'])}" for n in NS)
        print(f"{cap}: incidents={r['incidents']:4d}  {rec}  edge_only={r['episodes_only_in_capture_edge']}")
        t = r["tie_sensitivity"][10]
        if t:
            print(f"    tie@10: {t['tie_size']} tied for {t['open_slots']} slots, recall mean "
                  f"{t['recall']['mean']:.3f} (min {t['recall']['min']:.3f}, max {t['recall']['max']:.3f})")
        for ep, g in r["diagnosis"].items():
            print(f"    {ep} max_score={g['max_window_score']} candidate={g['candidate']} best_rank={g['best_rank']}")


def summary_at_10(threshold, result):
    return {"threshold": round(threshold, 4),
            **{cap: f"{r['recall'][10]['matched']}/{len(r['denominator'])} (incidents {r['incidents']})"
               for cap, r in result.items()}}
