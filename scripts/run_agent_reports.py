"""단계 5b-2: 사례마다 LLM 1회 보고서를 만들고 검증한다. 실패하면 템플릿 보고서를 쓴다(설계 9.1절).

입력: scripts/build_agent_inputs.py의 결과 폴더(기본: 해당 세트의 가장 최근 폴더), configs/agent/report.v1.json.
출력: outputs/agent/reports/<시각>-<세트>/<사건 번호>.json, summary.json, manifest.json.
LLM에는 입력 기록의 llm_input 부분만 보낸다. 오류 기록에는 예외 종류만 남긴다(입력이 섞이지 않게).
예: python scripts/run_agent_reports.py --set dev
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
from zeek_ad.llm_report import REPORT_VERSION, call_llm, final_report  # noqa: E402
from zeek_ad.provenance import file_record  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "agent" / "report.v1.json"
INPUT_ROOT = PROJECT_ROOT / "outputs" / "agent" / "inputs"
OUT_ROOT = PROJECT_ROOT / "outputs" / "agent" / "reports"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", choices=["dev", "eval"], required=True)
    parser.add_argument("--inputs", help="입력 폴더(기본: 이 세트의 가장 최근 폴더)")
    parser.add_argument("--cases", nargs="*", help="일부 사례만(예: dev-01 dev-11)")
    args = parser.parse_args()

    from google import genai

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    prompt_path = PROJECT_ROOT / config["system_prompt"]
    system_prompt = prompt_path.read_text(encoding="utf-8")
    inputs = Path(args.inputs) if args.inputs else sorted(INPUT_ROOT.glob(f"*-{args.set}"))[-1]
    files = sorted(inputs.glob(f"{args.set}-*.json"))
    if args.cases:
        files = [f for f in files if f.stem in set(args.cases)]

    client = genai.Client(api_key=load_env()["GEMINI_API_KEY"],
                          http_options={"api_version": config["api_version"],
                                        "timeout": config["timeout_seconds"] * 1000})
    run = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{args.set}"
    out = OUT_ROOT / run
    out.mkdir(parents=True)
    rows = []
    for f in files:
        rec = json.loads(f.read_text(encoding="utf-8"))
        call = call_llm(client, config, system_prompt, rec["llm_input"])
        report, kind, verification = final_report(call, rec["llm_input"], rec["template_report"])
        result = {"case_id": rec["case_id"], "incident_id": rec["incident_id"], "input_file": f.name,
                  "report_kind": kind, "report": report, "verification": verification, "llm_call": call}
        (out / f"{rec['case_id']}.json").write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n",
                                                    encoding="utf-8")
        rows.append({"case_id": rec["case_id"], "kind": kind, "reason": verification["reason"],
                     "problems": len(verification["problems"]), "model_version": call["model_version"],
                     "seconds": call["seconds"], "usage": call["usage"],
                     "llm_send": (call["report"] or {}).get("send_recommendation", {}).get("choice")})
        print(f"{rec['case_id']} {kind:8s} {verification['reason'] or ''} 문제 {len(verification['problems'])} "
              f"| {call['model_version']} {call['seconds']}s", flush=True)

    summary = {
        "cases": len(rows),
        "report_kind": dict(Counter(r["kind"] for r in rows)),
        "fallback_reason": dict(Counter(r["reason"] for r in rows if r["reason"])),
        "model_version": dict(Counter(r["model_version"] for r in rows)),
        "llm_send": dict(Counter(r["llm_send"] for r in rows)),
        "seconds": {"mean": round(sum(r["seconds"] for r in rows) / max(len(rows), 1), 1),
                    "max": max((r["seconds"] for r in rows), default=None)},
        "tokens": {k: sum((r["usage"] or {}).get(k) or 0 for r in rows) for k in ("input", "output", "thinking")},
        "cases_detail": rows,
    }
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    manifest = {"set": args.set, "report_version": REPORT_VERSION, "inputs": str(inputs.relative_to(PROJECT_ROOT)),
                "inputs_manifest": file_record(inputs / "manifest.json"), "config": file_record(CONFIG),
                "system_prompt": file_record(prompt_path)}
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "cases_detail"}, ensure_ascii=False))
    print(f"결과: outputs/agent/reports/{run}/")


if __name__ == "__main__":
    main()
