"""outputs/eval의 모델별 최신 결과를 모아 16건 합계 Recall@N과 사건 단위 bootstrap 95% 구간 표를 만든다(DD-006).

평가를 다시 하지 않는다. 각 run의 metrics.json에 저장된 일대일 대응(matching)만 읽는다.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.evaluation import bootstrap_recall_ci, pooled_hits  # noqa: E402
from zeek_ad.experiment import EVAL_CAPTURES, NS  # noqa: E402

# 표의 행 순서. 자명한 기준선을 맨 위에 둔다. 목록에 없는 모델은 뒤에 붙는다.
ORDER = ["nat_presence", "nat_count", "new_external_peers", "tail_rarity", "tail_rarity_v2", "iforest", "iforest_v2",
         "transformer", "transformer_v2", "tgn_recon", "tgn_shift", "first_seen", "first_seen_no_nat"]


def latest_runs(eval_dir):
    runs = {}
    for metrics in sorted(eval_dir.glob("*/metrics.json")):  # 이름이 시각으로 시작하므로 마지막이 최신
        runs[json.loads(metrics.read_text(encoding="utf-8"))["model"]] = metrics
    return dict(sorted(runs.items(), key=lambda kv: (ORDER.index(kv[0]) if kv[0] in ORDER else len(ORDER), kv[0])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-dir", type=Path, default=PROJECT_ROOT / "outputs" / "eval")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "eval" / "_summary")
    args = parser.parse_args()

    rows, table = [], {}
    header = ["모델", *[c.removeprefix("cic17-") + "@10" for c in EVAL_CAPTURES],
              *[f"합계@{n} [95% 구간]" for n in NS], "run"]
    for model, path in latest_runs(args.eval_dir).items():
        m = json.loads(path.read_text(encoding="utf-8"))
        days = m["days"]
        per_day = [f"{days[c]['recall']['10']['matched']}/{len(days[c]['denominator'])}" for c in EVAL_CAPTURES]
        pooled = {}
        for n in NS:
            hits = pooled_hits(days, n)
            pooled[n] = {**bootstrap_recall_ci(hits.values()), "matched": sum(hits.values()), "hits": hits}
        cells = [f"{pooled[n]['matched']}/{pooled[n]['episodes']} [{pooled[n]['low']:.2f}, {pooled[n]['high']:.2f}]"
                 for n in NS]
        rows.append([model, *per_day, *cells, path.parent.name])
        table[model] = {"run": path.parent.name, "threshold": m["threshold"], "pooled": pooled}

    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    text = "\n".join(lines)
    print(text)
    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    note = ("구간: 에피소드 16건을 복원 추출한 bootstrap(1,000회, seed 42) 백분위수 95%. "
            "같은 날 공격끼리의 의존성과 큐 경쟁은 반영하지 않는 근사다. 하루 단위 상위 N 예산은 그대로다.\n\n")
    (args.out / f"summary-{stamp}.md").write_text(note + text + "\n", encoding="utf-8")
    (args.out / f"summary-{stamp}.json").write_text(json.dumps(table, ensure_ascii=False, indent=2) + "\n",
                                                    encoding="utf-8")


if __name__ == "__main__":
    main()
