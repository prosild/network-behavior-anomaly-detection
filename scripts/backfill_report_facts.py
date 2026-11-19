"""migration 011 전에 저장된 보고서(agent_report)에 사실 목록(facts)과 가명표(pseudonyms)를 채운다. 한 번 쓰는 도구다.

- facts: 보고서를 쓸 때 LLM에 보낸 사실 목록. 저장된 입력 파일(outputs/agent/inputs)이 있으면 그것을 쓰고,
  없으면(LangGraph로 다시 만든 사건 등) 같은 규칙으로 다시 계산한다. 둘 다 있는 사건은 서로 같은지 확인한다.
- pseudonyms: 근거 JSON에서 다시 계산한다(agent_inputs.pseudonym_map).
- 확인: 사실 목록과 보고서 글에 나오는 가명(H, I1, X1 …)이 모두 가명표에 있어야 한다. 하나라도 어긋나면 쓰지 않고 멈춘다.
실행: python scripts/backfill_report_facts.py          (이미 채운 행은 건너뛴다. --all이면 다시 쓴다)
"""

import argparse
import json
from pathlib import Path
import re
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.agent_inputs import InputContext, collect_evidence, incident_facts, pseudonym_map  # noqa: E402
from zeek_ad.db import connect  # noqa: E402

INPUTS = PROJECT_ROOT / "outputs" / "agent" / "inputs"
PSEUDONYM = re.compile(r"(?<![A-Za-z0-9_])(H|[IX]\d+)(?![A-Za-z0-9_])")


def saved_inputs():
    """세트(dev·eval)마다 가장 최근 입력 폴더의 사실 목록. 키: (job_id, incident_id)."""
    found = {}
    for set_name in ("dev", "eval"):
        folder = sorted(INPUTS.glob(f"*-{set_name}"))[-1]
        for f in folder.glob(f"{set_name}-*.json"):
            inp = json.loads(f.read_text(encoding="utf-8"))
            found[(inp["job_id"], inp["incident_id"])] = inp["llm_input"]["facts"]
    return found


def used_pseudonyms(*objs):
    """사실 값과 보고서 글에 나온 가명. 사실 이름(키)이 아니라 값만 본다."""
    names = set()
    for obj in objs:
        names |= set(PSEUDONYM.findall(json.dumps(obj, ensure_ascii=False)))
    return names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="이미 채운 행도 다시 쓴다")
    args = parser.parse_args()
    saved, ctx = saved_inputs(), InputContext()
    with connect("zeekad_worker") as conn:
        conn.execute("SET search_path = zeekad")
        where = "" if args.all else "WHERE facts IS NULL"
        todo = conn.execute(f"SELECT job_id, incident_id, report FROM agent_report {where} ORDER BY 1, 2").fetchall()
        updates, from_file, same = [], 0, 0
        for job, iid, report in todo:
            recomputed, _ = incident_facts(conn, ctx, job, iid)
            facts = saved.get((job, iid))
            if facts is None:
                facts = recomputed
            else:
                from_file += 1
                if facts != recomputed:
                    sys.exit(f"저장된 입력과 다시 계산한 사실 목록이 다르다: {job} {iid}")
                same += 1
            table = pseudonym_map(collect_evidence(conn, job, iid), ctx.nets)
            missing = used_pseudonyms([f["value"] for f in facts], report) - set(table)
            if missing:
                sys.exit(f"가명표에 없는 가명 {sorted(missing)}: {job} {iid}")
            updates.append((json.dumps(facts, ensure_ascii=False), json.dumps(table), job, iid))
        for row in updates:
            conn.execute("UPDATE agent_report SET facts = %s::jsonb, pseudonyms = %s::jsonb "
                         "WHERE job_id = %s AND incident_id = %s", row)
        conn.commit()
    print(f"채움 {len(updates)}건: 저장된 입력 파일 {from_file}건(다시 계산과 같음 {same}건), "
          f"다시 계산만 {len(updates) - from_file}건")


if __name__ == "__main__":
    main()
