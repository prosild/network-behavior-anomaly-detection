"""단계 5b-3: 전송 판단 결과를 정답 에피소드와 맞춰 비교한다(DD-014). 호출 없이 DB와 정답 파일만 읽는다.

공격 관련 = 사건 창이 정답 창과 하나라도 겹침(평가기 episode_edges와 같은 규칙).
- CIC 캡처: confirmed 에피소드만.
- 합성 캡처: 주입 에피소드 + 같은 날 CIC confirmed 에피소드(합성은 CIC 날에 주입한 것).
지금 보냄 = choice가 send. analyst_review·need_more_evidence는 "지금 보내지 않음"으로 세고 따로 보인다.
예: python scripts/score_send_decisions.py --run outputs/agent/send/<시각>-dev
"""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect  # noqa: E402

CIC_EPISODES = PROJECT_ROOT / "configs" / "ground-truth" / "cic17-episodes.v1.json"
CIC_WINDOWS = PROJECT_ROOT / "outputs" / "ground_truth" / "cic17_v1" / "windows"
SYN_WINDOWS = PROJECT_ROOT / "outputs" / "synthetic" / "apt_v1" / "truth" / "windows.parquet"
METHODS = ["policy", "llm", "decision_model", "mandatory_or_decision"]


def truth_index():
    """(캡처, 자산, 역할, 창 시작 epoch) → 에피소드 ID 집합."""
    confirmed = {e["episode_id"] for e in json.loads(CIC_EPISODES.read_text(encoding="utf-8"))["episodes"]
                 if e["status"] == "confirmed"}
    cic = pd.read_parquet(CIC_WINDOWS)
    cic = cic[cic.episode_id.isin(confirmed)]
    syn = pd.read_parquet(SYN_WINDOWS)
    index = defaultdict(set)
    for r in cic.itertuples():
        index[(r.capture_id, str(r.asset_id), r.role, int(r.window_start))].add(r.episode_id)
        # 같은 날 합성 캡처에도 CIC 공격은 그대로 들어 있다
        index[(r.capture_id.replace("cic17-", "syn1-"), str(r.asset_id), r.role, int(r.window_start))].add(r.episode_id)
    for r in syn.itertuples():
        index[(r.capture_id, str(r.asset_id), r.role, int(r.window_start))].add(r.episode_id)
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, help="run_send_decisions.py 결과 폴더")
    args = parser.parse_args()
    run = Path(args.run)
    index = truth_index()
    rows = []
    with connect("zeekad_api") as conn:
        for f in sorted(run.glob("*-[0-9][0-9].json")):
            r = json.loads(f.read_text(encoding="utf-8"))
            job = json.loads((PROJECT_ROOT / "outputs" / "agent" / "inputs").joinpath(
                json.loads((run / "manifest.json").read_text())["inputs"].split("/")[-1], f.name).read_text())["job_id"]
            cap, asset, role, _ = r["incident_id"].split("|")
            windows = [int(w.timestamp()) for (w,) in conn.execute(
                "SELECT window_start FROM incident_window WHERE job_id = %s AND incident_id = %s",
                (job, r["incident_id"])).fetchall()]
            episodes = sorted(set().union(*(index.get((cap, asset, role, w), set()) for w in windows)))
            s = r["shadow"]
            choices = {"policy": s["policy"], "llm": s["llm"], "decision_model": s["decision_model"],
                       "mandatory_or_decision": "send" if s["mandatory"] or s["decision_model"] == "send"
                       else s["decision_model"]}
            rows.append({"case_id": r["case_id"], "capture": cap, "asset": asset, "role": role,
                         "attack_related": bool(episodes), "episodes": episodes, "mandatory": s["mandatory"],
                         **choices, "dm_send_prob": r["decision_model"]["probabilities"]["send"]})
    df = pd.DataFrame(rows)
    table = []
    for m in METHODS:
        send = df[m] == "send"
        table.append({"method": m, "send": int(send.sum()),
                      "review_or_more": int(df[m].isin(["analyst_review", "need_more_evidence"]).sum()),
                      "hold": int((df[m] == "hold").sum()),
                      "missed_attack": int((df.attack_related & ~send).sum()),
                      "unneeded_send": int((~df.attack_related & send).sum())})
    summary = {"cases": len(df), "attack_related": int(df.attack_related.sum()), "methods": table,
               "rows": rows}
    (run / "scored.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    pd.set_option("display.width", 200)
    print(df[["case_id", "capture", "asset", "role", "attack_related", "episodes", "mandatory", "policy", "llm",
              "decision_model", "dm_send_prob"]].to_string(index=False))
    print(f"\n공격 관련 {int(df.attack_related.sum())}/{len(df)}")
    print(pd.DataFrame(table).to_string(index=False))


if __name__ == "__main__":
    main()
