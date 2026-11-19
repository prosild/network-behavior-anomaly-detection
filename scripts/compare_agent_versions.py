"""DD-002 비교: 같은 사건을 일반 함수 버전(agent_pipeline)과 LangGraph 버전(agent_graph)으로 처리해 결과·지연을 비교한다.

DB 결과 표에는 쓰지 않는다(persist=False). LangGraph 쪽은 메모리 checkpoint를 쓴다(분석가 대기면 거기서 멈춘다).
예: python scripts/compare_agent_versions.py --set eval --cases eval-11 eval-14 eval-20
"""

import argparse
import json
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from run_agent_graph import resources  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", default="eval")
    parser.add_argument("--cases", nargs="+", required=True)
    args = parser.parse_args()

    from langgraph.checkpoint.memory import InMemorySaver
    from zeek_ad.agent_graph import build_graph
    from zeek_ad.agent_pipeline import run_incident

    res = {**resources(), "persist": False, "source": "compare"}
    graph = build_graph(res, InMemorySaver())
    inputs = sorted((PROJECT_ROOT / "outputs" / "agent" / "inputs").glob(f"*-{args.set}"))[-1]
    rows = []
    for case in args.cases:
        rec = json.loads((inputs / f"{case}.json").read_text(encoding="utf-8"))
        job, iid = rec["job_id"], rec["incident_id"]
        t = time.time()
        fn = run_incident(res, job, iid)
        fn_total = time.time() - t
        t = time.time()
        cfg = {"configurable": {"thread_id": f"compare|{job}|{iid}"}}
        gs = graph.invoke({"job_id": job, "incident_id": iid}, cfg)
        g_total = time.time() - t
        g_timing = {}
        for tr in gs["trace"]:
            g_timing[tr["node"]] = round(g_timing.get(tr["node"], 0) + tr["seconds"], 2)
        same = {
            "facts": fn["facts"] == gs["llm_input"]["facts"],
            "query": fn["query"] == gs["llm_input"]["query"],
            "candidates": fn["candidates"] == [d["attack_id"] for d in gs["llm_input"]["attack_candidates"]],
            "policy": fn["policy"] == gs["policy"]["choice"],
            "report_kind": fn["report_kind"] == gs["report_kind"],
            "llm_choice": fn["llm_choice"] == gs["shadow"]["llm"],
            "decision_model": fn["decision_model"] == gs["decision"]["choice"],
            "would_send": fn["would_send"] == gs["shadow"]["would_send"],
            "stops_for_review": (fn["status"] == "awaiting_review") == bool(graph.get_state(cfg).next),
        }
        rows.append({"case": case, "same": same, "function": {"total": round(fn_total, 2), **fn["timing"]},
                     "graph": {"total": round(g_total, 2), **g_timing},
                     "choices": {"function": [fn["llm_choice"], fn["decision_model"]],
                                 "graph": [gs["shadow"]["llm"], gs["decision"]["choice"]]}})
        print(json.dumps(rows[-1], ensure_ascii=False))
    out = PROJECT_ROOT / "outputs" / "agent" / "compare" / f"{time.strftime('%Y%m%dT%H%M%S')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(out.relative_to(PROJECT_ROOT))


if __name__ == "__main__":
    main()
