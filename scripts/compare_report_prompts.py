"""보고서 시스템 프롬프트를 바꾸기 전에, 같은 사례 묶음을 새 프롬프트로 돌려 기존 결과와 견준다(Q82).

운영 프롬프트는 평가 때의 프롬프트와 같게 둔다는 원칙(Q64)이 있다. 프롬프트를 바꾸려면 검증 통과 수와
전송 권고가 나빠지지 않는지를 먼저 본다. 평가 동결 도구(scripts/run_agent_reports.py)는 고치지 않고,
같은 입력 기록(scripts/build_agent_inputs.py의 결과)을 읽어 따로 돌린다. DB에는 쓰지 않는다.

- 사례마다 LLM을 1번 부른다(운영 설정 configs/agent/report.v2.json의 모델·온도). 차례로 부르고 --pause초 쉰다.
- 검증은 두 가지로 본다: 평가 때와 같은 검증(llm_report.final_report)과 운영 경로(report_guard.guarded_final_report).
- 문장에 내부 키 이름이 나오는지 센다(정의는 key_name_set).
- 기준 결과(--baseline, 기본: 그 세트의 가장 최근 보고서 폴더)와 사례별로 나란히 놓는다.
- 호출 오류는 HTTP 상태 코드만 남긴다. 429(한도 초과)가 나오면 한도 정보(status, quotaMetric·quotaId, retryDelay)만
  출력하고 그 사례까지 쓰고 멈춘다.
- --resume <폴더>: 멈춘 실행을 이어 간다. 오류 없이 끝난 사례는 두고 나머지만 다시 부른다.
- --recount <폴더...>: 저장된 응답으로 키 이름만 다시 센다(호출 없음).
출력: outputs/agent/prompt-compare/<시각>-<세트>-<프롬프트 이름>/{cases.jsonl, summary.json}
예: python scripts/compare_report_prompts.py --set eval --prompt configs/agent/prompts/report-system.v3.txt --pause 3
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import load_env  # noqa: E402
from zeek_ad.llm_report import SCHEMA, call_llm, final_report  # noqa: E402
from zeek_ad.provenance import file_record  # noqa: E402
from zeek_ad.report_guard import guarded_final_report  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "agent" / "report.v2.json"
INPUTS = PROJECT_ROOT / "outputs" / "agent" / "inputs"
REPORTS = PROJECT_ROOT / "outputs" / "agent" / "reports"
OUT = PROJECT_ROOT / "outputs" / "agent" / "prompt-compare"

# 키 이름 후보: 영문 낱말이 밑줄이나 점으로 이어진 토큰. 그중 key_name_set에 든 것만 센다.
TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[._][A-Za-z0-9]+)+")
SKIP_FIELDS = {"fact_ids", "attack_ids", "choice", "report_version"}


def _keys(value):
    """JSON 값 안의 모든 키(중첩 포함)."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _keys(v)
    elif isinstance(value, list):
        for v in value:
            yield from _keys(v)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


SCHEMA_KEYS = {k for k in _keys(SCHEMA) if k not in {"type", "properties", "items", "required", "enum"}}


def key_name_set(llm_input):
    """그 사례에서 '키 이름'으로 셀 토큰의 집합.

    넣는 것: 사실 이름(점으로 나눈 조각 포함), 사실 값 안의 JSON 키, 보고서 스키마의 키.
    빼는 것: 사실 값으로 들어 있는 문자열(서비스 이름 ldap_tcp, 연산 이름 ept_map 등), 모델 식별자,
    protocol.* 사실 이름의 뒤 조각(dce_rpc, krb_tcp 같은 Zeek 서비스 이름이라 사실 값의 서비스 이름과 같다).
    """
    names = set(SCHEMA_KEYS)
    for fact in llm_input["facts"]:
        names.add(fact["name"])
        names |= set(fact["name"].split("."))
        names |= set(_keys(fact["value"]))
    excluded = {s for fact in llm_input["facts"] for s in _strings(fact["value"])}
    excluded |= set(llm_input.get("model_descriptions", {}))
    excluded |= {f["name"].split(".", 1)[1] for f in llm_input["facts"] if f["name"].startswith("protocol.")}
    return names - excluded


def prose(value):
    """보고서에서 사람이 읽는 문장만 꺼낸다(사실 번호·ATT&CK ID·선택 값은 뺀다)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from prose(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in SKIP_FIELDS:
                yield from prose(item)


def key_names(report, llm_input):
    """문장에 나온 내부 키 이름(토큰이 나온 횟수만큼, 정렬)."""
    allowed = key_name_set(llm_input)
    return sorted(m for text in prose(report or {}) for m in TOKEN.findall(text) if m in allowed)


def quota_info(error):
    """429 오류 본문에서 한도 정보만 꺼낸다(키·요청 내용은 꺼내지 않는다)."""
    body = getattr(error, "details", None) or {}
    err = body.get("error", body) if isinstance(body, dict) else {}
    info = {"code": getattr(error, "code", None), "status": err.get("status") if isinstance(err, dict) else None,
            "violations": [], "retryDelay": None}
    for detail in (err.get("details") or []) if isinstance(err, dict) else []:
        if not isinstance(detail, dict):
            continue
        for v in detail.get("violations") or []:
            if isinstance(v, dict) and ("quotaMetric" in v or "quotaId" in v):
                info["violations"].append({k: v.get(k) for k in ("quotaMetric", "quotaId", "quotaValue", "quotaDimensions")})
        if "retryDelay" in detail:
            info["retryDelay"] = detail["retryDelay"]
    return info


class StatusRecorder:
    """client.models를 감싸 호출 오류의 HTTP 상태 코드(429면 한도 정보도)만 모은다. call_llm(평가 동결)은 오류 종류 이름만 남긴다."""

    def __init__(self, models):
        self.models, self.codes, self.quota = models, [], []

    def generate_content(self, **kwargs):
        try:
            return self.models.generate_content(**kwargs)
        except Exception as e:  # 오류 문장에는 입력이 섞일 수 있어 상태 코드와 한도 정보만 남기고 그대로 다시 던진다
            self.codes.append(getattr(e, "code", None))
            if getattr(e, "code", None) == 429:
                self.quota.append(quota_info(e))
            raise


class RecordingClient:
    def __init__(self, client):
        # 원래 클라이언트를 붙잡아 둔다. 놓치면 가비지 수거 때 HTTP 연결이 닫혀 호출이 RuntimeError로 끝난다
        self.client, self.models = client, StatusRecorder(client.models)


def latest(folder, name):
    runs = sorted(p for p in folder.glob(f"*-{name}") if p.is_dir())
    if not runs:
        raise SystemExit(f"{folder}에 {name} 세트의 폴더가 없다")
    return runs[-1]


def summarize(rows, prefix):
    """사례 기록 목록 → 요약(통과 수, 전송 권고 분포, 키 이름이 나온 사례 수·횟수)."""
    return {"cases": len(rows),
            "llm_reports": sum(r[f"{prefix}_kind"] == "llm" for r in rows),
            "send_choices": dict(Counter(r[f"{prefix}_send"] for r in rows)),
            "cases_with_key_names": sum(bool(r[f"{prefix}_key_names"]) for r in rows),
            "key_name_mentions": sum(len(r[f"{prefix}_key_names"]) for r in rows)}


def counts(rows):
    """summary.json에서 사례 기록으로 다시 계산하는 칸."""
    return {"old": summarize(rows, "old"), "new": summarize(rows, "new"),
            "new_ops_llm_reports": sum(r["new_ops_kind"] == "llm" for r in rows),
            "send_changed": [r["case_id"] for r in rows if r["old_send"] != r["new_send"]],
            "kind_changed": [r["case_id"] for r in rows if r["old_kind"] != r["new_kind"]],
            "errors": [r["case_id"] for r in rows if r["new_error"]]}


def read_cases(folder):
    return [json.loads(line) for line in (folder / "cases.jsonl").read_text(encoding="utf-8").splitlines()]


def write_cases(folder, records):
    (folder / "cases.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records),
                                        encoding="utf-8")


def recount(folders):
    """저장된 응답과 기준 보고서로 키 이름만 다시 센다. summary.json의 프롬프트 기록(해시)은 그대로 둔다."""
    for folder in folders:
        folder = folder if folder.is_absolute() else PROJECT_ROOT / folder
        summary = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
        inputs, baseline = PROJECT_ROOT / summary["inputs"], PROJECT_ROOT / summary["baseline"]
        records = read_cases(folder)
        for r in records:
            llm_input = json.loads((inputs / f"{r['case_id']}.json").read_text(encoding="utf-8"))["llm_input"]
            old = json.loads((baseline / f"{r['case_id']}.json").read_text(encoding="utf-8"))
            new = (r.get("new_raw") or {}).get("report")
            r["old_key_names"] = key_names((old.get("llm_call") or {}).get("report") or {}, llm_input)
            r["new_key_names"] = key_names(new if isinstance(new, dict) else None, llm_input)
        write_cases(folder, records)
        rows = sorted(({k: v for k, v in r.items() if k != "new_raw"} for r in records), key=lambda r: r["case_id"])
        summary.update(counts(rows))
        summary["key_names_recounted_at_utc"] = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        (folder / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(folder.name, json.dumps({k: summary[k] for k in ("old", "new")}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--set", choices=["dev", "eval"], default="eval")
    parser.add_argument("--prompt", type=Path, help="견줄 시스템 프롬프트 파일")
    parser.add_argument("--inputs", type=Path, help="입력 폴더(기본: 이 세트의 가장 최근 폴더)")
    parser.add_argument("--baseline", type=Path, help="기준 보고서 폴더(기본: 이 세트의 가장 최근 폴더)")
    parser.add_argument("--cases", nargs="*", help="일부 사례만(예: eval-05 eval-11)")
    parser.add_argument("--resume", type=Path, help="이어 갈 결과 폴더(오류 없이 끝난 사례는 다시 부르지 않는다)")
    parser.add_argument("--recount", type=Path, nargs="+", help="이 결과 폴더들의 키 이름만 다시 센다(호출 없음)")
    parser.add_argument("--pause", type=float, default=0, help="호출 사이에 쉴 초")
    args = parser.parse_args()
    if args.recount:
        return recount(args.recount)
    if not args.prompt:
        parser.error("--prompt가 필요하다")

    inputs = args.inputs or latest(INPUTS, args.set)
    baseline = args.baseline or latest(REPORTS, args.set)
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    prompt_path = args.prompt if args.prompt.is_absolute() else PROJECT_ROOT / args.prompt
    system_prompt = prompt_path.read_text(encoding="utf-8")

    from google import genai
    client = RecordingClient(genai.Client(api_key=load_env()["GEMINI_API_KEY"],
                                          http_options={"api_version": config["api_version"]}))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    kept = []
    if args.resume:
        out = args.resume if args.resume.is_absolute() else PROJECT_ROOT / args.resume
        if not out.name.endswith(f"-{args.set}-{prompt_path.stem}"):
            raise SystemExit(f"{out.name}은 {args.set} 세트·{prompt_path.stem}의 결과 폴더가 아니다")
        kept = [r for r in read_cases(out) if not r["new_error"]]
    else:
        out = OUT / f"{stamp}-{args.set}-{prompt_path.stem}"
        out.mkdir(parents=True, exist_ok=True)
    done = {r["case_id"] for r in kept}
    rows = [{k: v for k, v in r.items() if k != "new_raw"} for r in kept]
    stopped_on_429, first = None, True
    with (out / "cases.jsonl").open("w", encoding="utf-8") as log:
        for record in kept:
            log.write(json.dumps(record, ensure_ascii=False) + "\n")
        for path in sorted(inputs.glob(f"{args.set}-*.json")):
            case = json.loads(path.read_text(encoding="utf-8"))
            if (args.cases and case["case_id"] not in args.cases) or case["case_id"] in done:
                continue
            if not first and args.pause:
                time.sleep(args.pause)
            first = False
            client.models.codes, client.models.quota = [], []
            raw = call_llm(client, config, system_prompt, case["llm_input"])
            # 평가 때와 같은 검증(동결 함수)과 운영 경로(형식 검사 + 같은 검증)를 따로 본다
            try:
                _, eval_kind, eval_verification = final_report(raw, case["llm_input"], case["template_report"])
            except Exception as e:  # noqa: BLE001 (동결 검증이 모양이 틀린 응답에서 멈추면 템플릿으로 세고 다음 사례로)
                eval_kind, eval_verification = "template", {"reason": f"verify {type(e).__name__}", "problems": []}
            _, ops_kind, ops_verification, _ = guarded_final_report(raw, case["llm_input"], case["template_report"])
            new_report = raw.get("report") if isinstance(raw.get("report"), dict) else None
            old = json.loads((baseline / path.name).read_text(encoding="utf-8"))
            old_report = (old.get("llm_call") or {}).get("report") or {}
            row = {"case_id": case["case_id"],
                   "old_kind": old["report_kind"], "old_send": (old_report.get("send_recommendation") or {}).get("choice"),
                   "old_key_names": key_names(old_report, case["llm_input"]),
                   "new_kind": eval_kind, "new_ops_kind": ops_kind,
                   "new_send": ((new_report or {}).get("send_recommendation") or {}).get("choice"),
                   "new_key_names": key_names(new_report, case["llm_input"]),
                   "new_problems": len(eval_verification.get("problems", [])),
                   "new_ops_reason": ops_verification.get("reason"),
                   "new_error": raw.get("error"), "error_codes": client.models.codes, "quota": client.models.quota,
                   "seconds": raw.get("seconds"),
                   "model_version": raw.get("model_version")}
            rows.append(row)
            log.write(json.dumps({**row, "new_raw": raw}, ensure_ascii=False) + "\n")
            log.flush()
            print(f"{row['case_id']}: 기준 {row['old_kind']}/{row['old_send']} 키 {len(row['old_key_names'])} → "
                  f"새 {row['new_kind']}(운영 {row['new_ops_kind']})/{row['new_send']} 키 {len(row['new_key_names'])}"
                  f"{' 오류 ' + str(row['new_error']) + ' ' + str(row['error_codes']) if row['new_error'] else ''}",
                  flush=True)
            if 429 in row["error_codes"]:
                stopped_on_429 = row["case_id"]
                print("한도 정보:", json.dumps(row["quota"], ensure_ascii=False), flush=True)
                print(f"{row['case_id']}에서 429(한도 초과). 여기서 멈춘다. 나중에 --resume {out.relative_to(PROJECT_ROOT)}",
                      flush=True)
                break

    rows.sort(key=lambda r: r["case_id"])
    summary = {"set": args.set, "created_at_utc": out.name.split("-")[0], "config": file_record(CONFIG),
               "prompt": file_record(prompt_path), "inputs": str(inputs.relative_to(PROJECT_ROOT)),
               "baseline": str(baseline.relative_to(PROJECT_ROOT)), **counts(rows),
               "stopped_on_429": stopped_on_429, "resumed_at_utc": stamp if args.resume else None}
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ("old", "new", "new_ops_llm_reports", "send_changed", "kind_changed", "errors")},
                     ensure_ascii=False))
    print(f"written={out.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
