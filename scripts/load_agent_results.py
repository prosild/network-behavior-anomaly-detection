"""5b 파일 결과(보고서·전송 판단)를 DB 표 agent_report·send_decision에 넣는다(Q45: 이후 흐름은 DB에서 읽는다).

같은 사건이 이미 있으면 새 결과로 바꾼다(가장 최근 실행이 그 사건의 결과다).
예: python scripts/load_agent_results.py --set dev eval
"""

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.agent_inputs import ASSETS, collect_evidence, pseudonym_map  # noqa: E402
from zeek_ad.agent_store import save_decision, save_report  # noqa: E402
from zeek_ad.db import connect  # noqa: E402

AGENT = PROJECT_ROOT / "outputs" / "agent"


def latest(kind, set_name):
    return sorted((AGENT / kind).glob(f"*-{set_name}"))[-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", nargs="+", default=["dev", "eval"], dest="sets")
    args = parser.parse_args()
    nets = json.loads(ASSETS.read_text(encoding="utf-8"))["internal_networks"]
    with connect("zeekad_worker") as conn:
        for s in args.sets:
            inputs, reports, sends = latest("inputs", s), latest("reports", s), latest("send", s)
            n = 0
            for f in sorted(inputs.glob(f"{s}-*.json")):
                inp = json.loads(f.read_text(encoding="utf-8"))
                rep = json.loads((reports / f.name).read_text(encoding="utf-8"))
                snd = json.loads((sends / f.name).read_text(encoding="utf-8"))
                key = (inp["job_id"], inp["incident_id"])
                save_report(conn, *key, inp["llm_input"], rep["report"], rep["report_kind"], rep["verification"],
                            rep["llm_call"], reports.name, pseudonym_map(collect_evidence(conn, *key), nets))
                save_decision(conn, *key, snd["policy"], snd["llm"]["choice"], snd["decision_model"], snd["shadow"],
                              sends.name)
                n += 1
            print(f"{s}: {n}건 (보고서 {reports.name}, 판단 {sends.name})")


if __name__ == "__main__":
    main()
