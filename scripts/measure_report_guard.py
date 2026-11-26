"""형식 검사(zeek_ad.report_guard)의 규칙별 실측: 실제 LLM 응답에서 정상 응답을 거부하지 않는지 잰다.

입력: DB agent_report를 내보낸 CSV(기본 outputs/agent/analysis/agent_report_full.csv. 열: job_id, incident_id,
report_kind, report_version, created_at, report, llm_call, verification). git 제외 경로다.
원래 응답은 llm_call.report다. report_kind가 llm이면 동결 검증을 통과한 정상 응답, template이면 응답은 있었지만
검증에 실패한 것이다(형식 검사 전 기록이라 둘 다 원래 응답이 남아 있다).

출력(화면):
1. 규칙별 거부 수(정상 응답 / 검증 실패 응답)와 걸린 예(사건·위치). 정상 응답을 하나라도 거부하는 규칙은 켜면 안 된다.
2. 칸별 문자열 길이(최대·p99)와 응답 전체 길이. 길이 상한의 근거다.
3. 서식 문자(유니코드 범주 C*·Z*, 보통 공백 제외), 결합 문자(Mn·Me), 보이지 않는 문자(INVISIBLE), NFKC로 바뀌는 글자 수.
4. 배열별 항목 수(최대·p99). 항목 수 상한(ARRAY_MAX_ITEMS)의 근거다.

가명 규칙의 한계: CSV에는 사실 목록이 없다. outputs/agent/inputs/*/*.json(사례 입력 파일)에 같은 (작업, 사건)이 있으면
그 사실 목록의 가명을 쓴다. 없으면 같은 응답의 강한 검사 칸(주장·설명·전송 이유)에 나온 가명을 쓴다. 정상 응답에서는
이 가명들이 인용 사실 안에 있다고 동결 검증이 확인했으므로 사실 목록의 부분집합이다. 그래서 거부 수는 상한이다.
실행: python3 scripts/measure_report_guard.py [--csv 경로]
"""

import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from zeek_ad.report_guard import (ARRAY_MAX_ITEMS, ENABLED_RULES, INVISIBLE, PSEUDONYM_TOKEN,  # noqa: E402
                                  RULE_LABELS, fact_pseudonyms, rule_hits, schema_problems)

CSV = ROOT / "outputs" / "agent" / "analysis" / "agent_report_full.csv"
INPUTS = ROOT / "outputs" / "agent" / "inputs"


def percentile(values, q):
    xs = sorted(values)
    return xs[min(len(xs) - 1, round(q * (len(xs) - 1)))] if xs else None


def saved_facts():
    """사례 입력 파일의 (작업, 사건) → 사실 목록의 가명 집합."""
    out = {}
    for path in sorted(INPUTS.glob("*/*.json")):
        d = json.loads(path.read_text(encoding="utf-8"))
        if "llm_input" in d:
            out[(int(d["job_id"]), d["incident_id"])] = fact_pseudonyms(d["llm_input"]["facts"])
    return out


def strong_pseudonyms(report):
    texts = ([c.get("claim", "") for c in report.get("claims", [])]
             + [e.get("explanation", "") for e in report.get("possible_explanations", [])]
             + [report.get("send_recommendation", {}).get("reason", "")])
    return {t for x in texts for t in PSEUDONYM_TOKEN.findall(x)}


def strings(value, path="$", arrays=None):
    """(경로, 문자열)을 꺼낸다. arrays를 주면 배열 경로별 항목 수를 모은다. 경로의 번호는 []로 바꾼다."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from strings(v, f"{path}.{k}", arrays)
    elif isinstance(value, list):
        if arrays is not None:
            arrays[path].append(len(value))
        for v in value:
            yield from strings(v, f"{path}[]", arrays)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--csv", type=Path, default=CSV)
    args = ap.parse_args()
    if not args.csv.exists():
        print(f"입력이 없다: {args.csv}\nDB agent_report를 CSV로 내보낸 뒤 --csv로 준다(열은 맨 위 설명 참조).")
        return
    csv.field_size_limit(sys.maxsize)
    facts = saved_facts()
    counts = Counter()                       # (규칙, 종류) → 거부한 응답 수
    examples = defaultdict(list)
    lengths, totals, chars, arrays = defaultdict(list), [], Counter(), defaultdict(list)
    marks, invisible, nfkc = Counter(), Counter(), Counter()
    kinds, from_inputs = Counter(), Counter()
    with args.csv.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            report = (json.loads(row["llm_call"]) or {}).get("report")
            if report is None:
                continue
            kind = "정상(llm)" if row["report_kind"] == "llm" else "검증 실패(template)"
            kinds[kind] += 1
            key = (int(row["job_id"]), row["incident_id"])
            known = facts.get(key)
            from_inputs[kind] += known is not None
            if known is None:
                known = strong_pseudonyms(report)
            schema = schema_problems(report)
            hit_rules = {"schema": schema} if schema else {}
            for rule, path in rule_hits(report, known):
                hit_rules.setdefault(rule, []).append(path)
            for rule, paths in hit_rules.items():
                counts[(rule, kind)] += 1
                if len(examples[rule]) < 3:
                    examples[rule].append(f"{row['job_id']} {row['incident_id']} {paths[0]}")
            total = 0
            for path, text in strings(report, arrays=arrays):
                lengths[path].append(len(text))
                total += len(text)
                for c in text:
                    cat = unicodedata.category(c)
                    if cat[0] in "CZ" and c != " ":
                        chars[(cat, f"U+{ord(c):04X}")] += 1
                    if cat in ("Mn", "Me"):
                        marks[f"U+{ord(c):04X}"] += 1
                    if ord(c) in INVISIBLE:
                        invisible[f"U+{ord(c):04X}"] += 1
                    if unicodedata.normalize("NFKC", c) != c:
                        nfkc[f"U+{ord(c):04X}"] += 1
            totals.append(total)

    print(f"원래 응답: {dict(kinds)} (사실 목록을 입력 파일에서 찾은 응답: {dict(from_inputs)})")
    print("\n1. 규칙별 거부 응답 수")
    print(f"{'규칙':16s} {'켬':3s} {'정상(llm)':>10s} {'검증 실패':>10s}  설명")
    for rule in ["schema", *RULE_LABELS]:
        on = "예" if rule == "schema" or rule in ENABLED_RULES else "아니오"
        label = "형식(필수·타입·허용 값·스키마 밖 키)" if rule == "schema" else RULE_LABELS[rule]
        print(f"{rule:16s} {on:3s} {counts[(rule, '정상(llm)')]:>10d} {counts[(rule, '검증 실패(template)')]:>10d}  {label}")
        for e in examples[rule]:
            print(f"    예: {e}")
    print("\n2. 칸별 문자열 길이(자)")
    for path, xs in sorted(lengths.items()):
        print(f"  {path:45s} n={len(xs):6d} 최대={max(xs):5d} p99={percentile(xs, 0.99):5d}")
    print(f"  {'응답 전체(문자열 합)':45s} n={len(totals):6d} 최대={max(totals):5d} p99={percentile(totals, 0.99):5d}")
    print("\n3. 서식 문자(C*·Z*, 보통 공백 제외) 사용 수:", dict(chars) or 0)
    print("   결합 문자(Mn·Me):", dict(marks) or 0, "· 보이지 않는 문자:", dict(invisible) or 0,
          "· NFKC로 바뀌는 글자:", dict(nfkc) or 0)
    print("\n4. 배열별 항목 수(상한)")
    for path, xs in sorted(arrays.items()):
        print(f"  {path:45s} n={len(xs):6d} 최대={max(xs):5d} p99={percentile(xs, 0.99):5d} "
              f"상한={ARRAY_MAX_ITEMS.get(path, '-')}")


if __name__ == "__main__":
    main()
