"""alias가 가리키는 묶음으로 실제 추론을 해 보고, 저장된 채점 작업과 같은지 확인한다(설계 8절, 단계 7). DB에 쓰지 않는다.

교체·롤백 뒤 "실제로 어느 버전이 추론하는가"를 확인하는 데 쓴다. 채점 worker와 같은 경로를 탄다:
alias → 버전 번호로 고정 → 묶음 받기(manifest 해시·코드 호환 검사) → 창 점수 → 결합 큐.
같은 입력으로 이미 끝난 작업이 있으면 worker는 건너뛰므로(작업 = 입력 + 묶음), 롤백 확인에는 이 스크립트를 쓴다.
set에 큐 자격 규칙 항목(queue_eligibility)이 있으면 worker와 같이 적용하고, 창 점수는 split(라벨)까지 견준다.

예: python scripts/check_bundle.py --inputs outputs/live/runs/lab-20261119/rev-0014-664d94ac/worker-inputs.json \\
        --set live --capture lab-20261119 --compare-job 43
"""

import argparse
import json
import os
from pathlib import Path
import sys

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
import mlflow  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect, mlflow_tracking_uri  # noqa: E402
from zeek_ad.fusion import picked_score  # noqa: E402
from zeek_ad.queue_eligibility import apply_to_set  # noqa: E402
from zeek_ad.worker import resolve_bundle  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--alias", default="champion")
    parser.add_argument("--inputs", type=Path, required=True, help="입력 묶음 정의(worker-inputs.json)")
    parser.add_argument("--set", default="live")
    parser.add_argument("--capture", required=True)
    parser.add_argument("--compare-job", type=int, required=True, help="같은 입력으로 만든 작업 번호")
    args = parser.parse_args()

    mlflow.set_tracking_uri(mlflow_tracking_uri())
    bundle = resolve_bundle(args.alias)
    model = bundle["model"]
    cfg = json.loads(args.inputs.read_text(encoding="utf-8"))["sets"][args.set]
    bounds = {c["capture_id"]: c for c in json.loads((PROJECT_ROOT / cfg["bounds"]).read_text(encoding="utf-8"))["captures"]}
    b = bounds[args.capture]
    scores = model.score_capture(args.capture, PROJECT_ROOT / cfg["gold_dir"], PROJECT_ROOT / cfg["graph_dir"],
                                 b["packet_time_min"])
    # worker와 같이 set의 큐 자격 규칙을 적용한다(항목이 없으면 그대로)
    scores, queue_scores, _ = apply_to_set(scores, cfg, args.capture, PROJECT_ROOT)
    fused, sources, queues = model.build_queue(queue_scores, {args.capture: b["pcap_sha256"]})
    mine_scores = {(r.model_name, r.asset_id, r.role, int(r.window_start)):
                   (r.split, round(float(r.score), 9), bool(r.is_candidate)) for r in scores.itertuples(index=False)}
    mine_inc = [(k, i.incident_id, sources[i.incident_id][0], sorted(set(sources[i.incident_id][1:])),
                 round(picked_score(queues[sources[i.incident_id][0]], i), 9), list(i.windows))
                for k, i in enumerate(fused, 1)]

    with connect("zeekad_worker", autocommit=True) as conn:
        job_bundle = conn.execute("SELECT bundle_id FROM scoring_job WHERE job_id = %s", (args.compare_job,)).fetchone()[0]
        stored_scores = {(m, a, r, int(w)): (sp, round(s, 9), c) for m, a, r, w, sp, s, c in conn.execute(
            """SELECT model_name, host(asset_id), role, extract(epoch FROM window_start), split, score, is_candidate
               FROM window_score WHERE job_id = %s""", (args.compare_job,))}
        stored_inc = [(k, iid, p, sorted(a), round(s, 9), [int(w) for w in ws]) for k, iid, p, a, s, ws in conn.execute(
            """SELECT queue_rank, incident_id, picked_by, also_flagged_by, model_score,
                      (SELECT array_agg(extract(epoch FROM window_start)::bigint ORDER BY window_start)
                       FROM incident_window w WHERE w.job_id = i.job_id AND w.incident_id = i.incident_id)
               FROM incident i WHERE job_id = %s ORDER BY queue_rank""", (args.compare_job,))]

    same_scores = mine_scores == stored_scores
    same_inc = mine_inc == stored_inc
    print(f"alias {args.alias} → {bundle['bundle_id']} ({bundle['manifest']['bundle']}, "
          f"overlap_policy {model.fusion.get('overlap_policy', 'skip')})")
    print(f"비교 작업 {args.compare_job}({job_bundle}): 창 점수 {len(mine_scores)}행 같음 {same_scores}, "
          f"사건 {len(mine_inc)}건 같음 {same_inc}")
    return 0 if same_scores and same_inc else 1


if __name__ == "__main__":
    raise SystemExit(main())
