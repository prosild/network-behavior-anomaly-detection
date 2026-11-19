"""단계 5b-3: 사례마다 Slack 전송 판단 세 가지를 만들고 나란히 기록한다(그림자 비교, 실제 전송 없음).

입력: 입력 폴더(build_agent_inputs.py 결과), 보고서 폴더(run_agent_reports.py 결과, 일반 LLM 의견), configs/agent/send-decision.v1.json.
출력: outputs/agent/send/<시각>-<세트>/<사건 번호>.json, summary.json, manifest.json.
예: python scripts/run_send_decisions.py --set dev --cases dev-07 --show
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import load_env  # noqa: E402
from zeek_ad.provenance import file_record  # noqa: E402
from zeek_ad.send_decision import call_decision, decision_request, policy_decision, shadow_record  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "agent" / "send-decision.v1.json"
AGENT = PROJECT_ROOT / "outputs" / "agent"


def latest(kind, set_name):
    return sorted((AGENT / kind).glob(f"*-{set_name}"))[-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", choices=["dev", "eval"], required=True)
    parser.add_argument("--inputs")
    parser.add_argument("--reports")
    parser.add_argument("--cases", nargs="*")
    parser.add_argument("--show", action="store_true", help="보낸 요청과 받은 응답을 그대로 출력한다")
    args = parser.parse_args()

    from google import genai

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    dm = config["decision_model"]
    inputs = Path(args.inputs) if args.inputs else latest("inputs", args.set)
    reports = Path(args.reports) if args.reports else latest("reports", args.set)
    files = sorted(inputs.glob(f"{args.set}-*.json"))
    if args.cases:
        files = [f for f in files if f.stem in set(args.cases)]
    client = genai.Client(api_key=load_env()["GEMINI_API_KEY"],
                          http_options={"api_version": dm["api_version"], "timeout": dm["timeout_seconds"] * 1000})

    out = AGENT / "send" / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{args.set}"
    out.mkdir(parents=True)
    rows = []
    for f in files:
        rec = json.loads(f.read_text(encoding="utf-8"))
        report = json.loads((reports / f.name).read_text(encoding="utf-8"))
        policy = policy_decision(rec["llm_input"]["facts"], config["policy"])
        if args.show:
            req = decision_request(rec["llm_input"], dm)
            print("=== 보낸 요청: model =", dm["model"])
            print("questions =", json.dumps(req["questions"], ensure_ascii=False, indent=1))
            print(f"input = (llm_input JSON {len(req['input'])}자, 보고서 LLM에 보낸 것과 같다)")
        decision = call_decision(client, dm, rec["llm_input"])
        if args.show:
            print("=== 받은 응답:", json.dumps(decision, ensure_ascii=False, indent=1))
        shadow = shadow_record(policy, report["llm_call"]["report"], decision)
        result = {"case_id": rec["case_id"], "incident_id": rec["incident_id"], "policy": policy,
                  "llm": {"choice": shadow["llm"], "report_kind": report["report_kind"],
                          "reason": (report["llm_call"]["report"] or {}).get("send_recommendation", {}).get("reason")},
                  "decision_model": decision, "shadow": shadow}
        (out / f"{rec['case_id']}.json").write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n",
                                                    encoding="utf-8")
        rows.append({"case_id": rec["case_id"], **shadow, "confidence": decision["confidence"]})
        print(f"{rec['case_id']} 정책 {policy['choice']:4s}{'(필수)' if policy['mandatory'] else '      '} "
              f"| LLM {shadow['llm']} | 판단 모델 {decision['choice']} {decision['probabilities']}", flush=True)
    summary = {"cases": len(rows), "would_send": sum(r["would_send"] for r in rows),
               "policy": dict(Counter(r["policy"] for r in rows)), "llm": dict(Counter(r["llm"] for r in rows)),
               "decision_model": dict(Counter(r["decision_model"] for r in rows)), "rows": rows}
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    (out / "manifest.json").write_text(json.dumps({
        "set": args.set, "inputs": str(inputs.relative_to(PROJECT_ROOT)), "reports": str(reports.relative_to(PROJECT_ROOT)),
        "config": file_record(CONFIG)}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"결과: {out.relative_to(PROJECT_ROOT)}/")


if __name__ == "__main__":
    main()
