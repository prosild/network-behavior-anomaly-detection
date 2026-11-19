"""DB에 저장된 결합 큐를 다시 읽어 단계 3 결합 평가(fusion_v1)와 같은 Recall@N이 나오는지 확인한다.

입력부터 사건까지의 추적 확인이다: Registry 묶음 → worker → PostgreSQL → (이 스크립트) → 평가 결과.
읽기 전용 계정(zeekad_api)으로 읽는다. 합성 캡처는 DB에 전체 큐(CIC 사건 포함)가 있으므로 결합 평가의 "all" 큐와 비교한다.
"""

import argparse
import json
from pathlib import Path
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect  # noqa: E402
from zeek_ad.evaluation import Incident, episode_edges, recall_at_n  # noqa: E402
from zeek_ad.synthetic_eval import NS  # noqa: E402

EVAL = PROJECT_ROOT / "outputs" / "eval"
FUSION_RUN = EVAL / "20261111T014619Z-fusion_v1"


def db_queues(bundle_id):
    """succeeded 작업마다 queue_rank 순서의 사건 목록(창 포함)을 돌려준다."""
    with connect("zeekad_api") as conn:
        jobs = conn.execute("""SELECT job_id, capture_id FROM scoring_job
                               WHERE bundle_id = %s AND status = 'succeeded'""", (bundle_id,)).fetchall()
        out = {}
        for job_id, cap in jobs:
            rows = conn.execute(
                """SELECT i.incident_id, host(i.asset_id), i.role, i.queue_rank,
                          extract(epoch FROM i.first_start)::bigint, extract(epoch FROM i.last_end)::bigint,
                          array_agg(extract(epoch FROM w.window_start)::bigint ORDER BY w.window_start)
                   FROM incident i JOIN incident_window w USING (job_id, incident_id)
                   WHERE i.job_id = %s GROUP BY 1, 2, 3, 4, 5, 6 ORDER BY i.queue_rank""", (job_id,)).fetchall()
            out[cap] = [Incident(incident_id=r[0], capture_id=cap, asset_id=r[1], role=r[2], first_start=r[4],
                                 last_end=r[5], score=-float(r[3]), windows=tuple(r[6]), tie_key="")
                        for r in rows]
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", default="zeekad-fusion/1")
    args = parser.parse_args()
    queues = db_queues(args.bundle)
    fusion = json.loads((FUSION_RUN / "metrics.json").read_text(encoding="utf-8"))

    cic_truth = pd.read_parquet(PROJECT_ROOT / "outputs" / "ground_truth" / "cic17_v1" / "windows")
    cic_truth["capture_id"] = cic_truth["capture_id"].astype(str)
    confirmed = {e["episode_id"] for e in json.loads((PROJECT_ROOT / "configs" / "ground-truth" / "cic17-episodes.v1.json")
                                                     .read_text(encoding="utf-8"))["episodes"] if e["status"] == "confirmed"}
    syn_truth = pd.read_parquet(PROJECT_ROOT / "outputs" / "synthetic" / "apt_v1" / "truth" / "windows.parquet")
    syn_ids = set(syn_truth.episode_id)

    problems = 0
    for cap, q in sorted(queues.items()):
        if cap.startswith("cic17"):
            truth, ids, ref = cic_truth[cic_truth.capture_id == cap], confirmed, fusion["cic_days"][cap]["fusion"]
        else:
            truth, ids, ref = syn_truth[syn_truth.capture_id == cap], syn_ids, fusion["synthetic_days"][cap]["all"]
        recs = truth.to_dict("records")
        denominator = {t["episode_id"] for t in recs} & ids
        edges = episode_edges(q, recs, ids)
        got = {n: recall_at_n(q, n, edges, denominator)["matched"] for n in NS}
        want = {n: ref["recall"][str(n)]["matched"] for n in NS}
        ok = got == want and len(q) == ref["incidents"]
        problems += not ok
        print(f"{cap}: incidents db={len(q)} eval={ref['incidents']}  recall db={got} eval={want}  {'OK' if ok else 'DIFF'}")
    if problems:
        sys.exit(f"불일치 {problems}개")


if __name__ == "__main__":
    main()
