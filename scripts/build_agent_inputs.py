"""단계 5b-1: 사례 사건마다 LLM 입력(사실 목록)·검색 질의 문장·ATT&CK 검색 결과·템플릿 보고서를 만든다.

입력: DB의 사건·근거(evidence.v1)·모델 창 점수, configs/agent/cases.v1.json, configs/rag/retrieval.v1.json,
      Gold v2 창 특징(사건 창 = configs/worker/inputs.v1.json의 캡처별 gold_dir, 비교 기준 = CIC 월요일 학습 창).
출력: outputs/agent/inputs/<시각>-<세트>/<사건 번호>.json 과 manifest.json. 실제 IP·날짜는 들어가지 않는다.
예: python scripts/build_agent_inputs.py --set dev
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.agent_inputs import (BASELINE_CAPTURE, BASELINE_GOLD, BASELINE_SPLIT, RETRIEVAL,  # noqa: E402
                                  WORKER_INPUTS, InputContext, assemble, incident_facts)
from zeek_ad.db import connect, load_env  # noqa: E402
from zeek_ad.llm_input import INPUT_VERSION, query_sentence, template_report  # noqa: E402
from zeek_ad.provenance import file_record  # noqa: E402
from zeek_ad.rag import retrieve  # noqa: E402

CASES = PROJECT_ROOT / "configs" / "agent" / "cases.v1.json"
OUT_ROOT = PROJECT_ROOT / "outputs" / "agent" / "inputs"


def latest_job(conn, capture_id):
    row = conn.execute("""SELECT job_id FROM scoring_job WHERE capture_id = %s AND status = 'succeeded'
                          ORDER BY finished_at DESC LIMIT 1""", (capture_id,)).fetchone()
    if row is None:
        sys.exit(f"{capture_id}: 성공한 채점 작업이 없다")
    return row[0]


def pick_cases(conn, entry):
    """캡처의 결합 큐 상위 N건. exclude_same_as가 있으면 그 캡처에도 있는 사건(자산·역할·시작 시각)은 뺀다."""
    job = latest_job(conn, entry["capture_id"])
    rows = conn.execute("""SELECT i.incident_id, i.queue_rank, host(i.asset_id), i.role, i.first_start, i.picked_by,
                                  i.also_flagged_by, e.evidence
                           FROM incident i JOIN incident_evidence e USING (job_id, incident_id)
                           WHERE i.job_id = %s ORDER BY i.queue_rank""", (job,)).fetchall()
    skip = set()
    if "exclude_same_as" in entry:
        other = latest_job(conn, entry["exclude_same_as"])
        skip = set(conn.execute("SELECT host(asset_id), role, first_start FROM incident WHERE job_id = %s",
                                (other,)).fetchall())
    picked = [r for r in rows if (r[2], r[3], r[4]) not in skip][:entry["top"]]
    return job, picked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", choices=["dev", "eval"], required=True)
    args = parser.parse_args()
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    ctx = InputContext()

    items = []
    with connect("zeekad_api") as conn:
        for entry in cases["sets"][args.set]:
            job, picked = pick_cases(conn, entry)
            for incident_id, *_ in picked:
                facts, _ = incident_facts(conn, ctx, job, incident_id)
                items.append({"capture_id": entry["capture_id"], "job_id": job, "incident_id": incident_id,
                              "facts": facts, "query": query_sentence(facts)})
        # 검색은 한 번에(임베딩 묶음 호출)
        found, method, error = retrieve(conn, [it["query"] for it in items], ctx.retrieval,
                                        load_env().get("GEMINI_API_KEY"))

    run = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{args.set}"
    out = OUT_ROOT / run
    out.mkdir(parents=True)
    for n, (it, docs) in enumerate(zip(items, found), 1):
        case = f"{args.set}-{n:02d}"
        # incident_id·capture_id는 사례를 되짚는 로컬 기록이다. LLM에는 llm_input 부분만 보낸다.
        record = {"case_id": case, "capture_id": it["capture_id"], "job_id": it["job_id"],
                  "incident_id": it["incident_id"], "retrieval_method": method,
                  "llm_input": assemble(it["facts"], docs),
                  "template_report": template_report(it["facts"], docs)}
        (out / f"{case}.json").write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    manifest = {"set": args.set, "cases": len(items), "input_version": INPUT_VERSION,
                "retrieval": {"method": method, "fallback_reason": error, **file_record(RETRIEVAL)},
                "cases_config": file_record(CASES), "worker_inputs": file_record(WORKER_INPUTS),
                "baseline": {"capture_id": BASELINE_CAPTURE, "split": BASELINE_SPLIT,
                             **file_record(BASELINE_GOLD / "manifest.json")}}
    (out / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"사례 {len(items)}건, 검색 {method}{' (대체: ' + error + ')' if error else ''}")
    print(f"결과: outputs/agent/inputs/{run}/")


if __name__ == "__main__":
    main()
