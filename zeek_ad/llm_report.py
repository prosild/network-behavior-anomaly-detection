"""LLM 1회 보고서와 검증·템플릿 대체(단계 5b-2, 설계 9.1절).

흐름: LLM 입력(llm-input.v2) → 구조화 출력(JSON 스키마) 호출 1회 → 코드 검증 → 통과하면 LLM 보고서, 아니면 템플릿.
- 호출 실패·시간 초과·형식 오류·검증 실패 모두 템플릿으로 대신한다. 사건은 그대로 남는다.
- LLM 출력은 검증에 실패해도 평가용으로 저장한다(화면에는 쓰지 않는다).

검증(코드로 할 수 있는 것만):
- 사실 ID가 실재하는가, ATT&CK ID가 검색 후보 안에 있는가.
- 주장·설명·전송 이유: 문장 속 숫자와 가명(H, I1, X1…)이 인용한 사실 안에 있는가(강한 검사).
- 관측 요약·한계·추가 확인: 사실 ID가 없으므로 숫자가 사실 목록 어딘가에 있는가만 본다(약한 검사).
방향·단위·해석이 맞는지는 코드로 알 수 없다. 사람 채점(설계 9.2절)에서 본다.
검증 함수는 표준 라이브러리만 쓴다. 호출 함수만 google-genai를 쓴다.
"""

import json
import re
import time

REPORT_VERSION = "llm-report.v1"
SEND_CHOICES = ["send", "hold", "need_more_evidence", "analyst_review"]
SCHEMA = {
    "type": "object",
    "properties": {
        "observation_summary": {"type": "string"},
        "claims": {"type": "array", "items": {"type": "object", "properties": {
            "claim": {"type": "string"}, "fact_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["claim", "fact_ids"]}},
        "possible_explanations": {"type": "array", "items": {"type": "object", "properties": {
            "explanation": {"type": "string"}, "attack_ids": {"type": "array", "items": {"type": "string"}},
            "fact_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["explanation", "attack_ids", "fact_ids"]}},
        "limitations": {"type": "array", "items": {"type": "string"}},
        "follow_up": {"type": "array", "items": {"type": "string"}},
        "send_recommendation": {"type": "object", "properties": {
            "choice": {"type": "string", "enum": SEND_CHOICES},
            "reason": {"type": "string"}, "fact_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["choice", "reason", "fact_ids"]},
    },
    "required": ["observation_summary", "claims", "possible_explanations", "limitations", "follow_up",
                 "send_recommendation"],
}

# 숫자: 앞에 영문자·숫자·점이 붙은 것은 식별자 일부라 뺀다(F43, X1, T1595.001, p95).
# 빼기 부호는 앞이 글자·숫자가 아닐 때만 부호로 본다. "gemini-3.8"의 3.8처럼 하이픈 뒤 숫자는 식별자로 보고 뺀다.
# 값이 아닌 용어도 뺀다: "95백분위수"(p95), "4xx"(HTTP 상태 범위). dev 실행에서 검증기가 잘못 잡은 두 경우다.
NUMBER = re.compile(r"(?:(?<![A-Za-z0-9_.])-|(?<![A-Za-z0-9_.\-]))\d(?:[\d,]*\d)?(?:\.\d+)?(?![\d]|xx|\s*백분위)")
PSEUDONYM = re.compile(r"(?<![A-Za-z0-9_])(H|[IX]\d+)(?![A-Za-z0-9_])")
ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _walk(value):
    """사실 값 안의 숫자·문자열·목록 길이를 모두 꺼낸다."""
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        yield ("num", float(value))
    elif isinstance(value, str):
        yield ("str", value)
    elif isinstance(value, list):
        yield ("num", float(len(value)))
        for v in value:
            yield from _walk(v)
    elif isinstance(value, dict):
        for v in value.values():
            yield from _walk(v)


def text_numbers(text):
    """문장 속 숫자(글자 그대로, 값). 천 단위 쉼표는 지운다."""
    out = []
    for m in NUMBER.finditer(text):
        raw = m.group(0).replace(",", "")
        if raw in ("", "-"):
            continue
        out.append((m.group(0), float(raw)))
    return out


def _matches(raw, number, allowed):
    """글자에 적힌 자릿수까지 반올림하면 같은 값이 허용 목록에 있는가."""
    decimals = len(raw.split(".")[1]) if "." in raw else 0
    tol = 0.5 * 10 ** -decimals + 1e-9
    return any(abs(number - a) <= tol for a in allowed)


def allowed_numbers(facts, extra=()):
    nums = {float(x) for x in extra}
    for f in facts:
        nums |= {v for k, v in _walk(f["value"]) if k == "num"}
    return nums


def fixed_numbers(llm_input):
    """고정 설명에 나오는 숫자와 모델 수. 5분 창, 12칸, "3개 모델 모두" 같은 정의라 어디서나 허용한다."""
    models = llm_input.get("model_descriptions", {})
    text = " ".join(llm_input.get("notes", [])) + " " + " ".join(models.values())
    return {n for _, n in text_numbers(text)} | {float(len(models))}


def check_text(text, facts_cited, fixed, where, problems, strong=True):
    """문장의 숫자·가명이 인용한 사실(약한 검사면 전체 사실)에 있는지 본다."""
    allowed = allowed_numbers(facts_cited, fixed)
    if strong:  # "세 모델 모두"처럼 인용한 사실 개수를 세는 경우
        allowed.add(float(len(facts_cited)))
    for raw, n in text_numbers(text):
        if not _matches(raw, n, allowed):
            problems.append({"where": where, "kind": "number_not_in_facts", "value": raw})
    if strong:
        names = {"H"} | {v for f in facts_cited for k, v in _walk(f["value"]) if k == "str"}
        for p in PSEUDONYM.findall(text):
            if p not in names:
                problems.append({"where": where, "kind": "pseudonym_not_in_facts", "value": p})


def verify_report(report, llm_input):
    """LLM 보고서 검증. 반환: 문제 목록(비어 있으면 통과)."""
    facts = llm_input["facts"]
    by_id = {f["id"]: f for f in facts}
    fixed = fixed_numbers(llm_input)
    candidates = {c["attack_id"] for c in llm_input.get("attack_candidates", [])}
    problems = []

    def cited(ids, where):
        unknown = [i for i in ids if i not in by_id]
        for i in unknown:
            problems.append({"where": where, "kind": "unknown_fact_id", "value": i})
        if not ids:
            problems.append({"where": where, "kind": "no_fact_ids", "value": None})
        return [by_id[i] for i in ids if i in by_id]

    if not report.get("claims"):
        problems.append({"where": "claims", "kind": "no_claims", "value": None})
    for k, c in enumerate(report.get("claims", []), 1):
        where = f"claims[{k}]"
        check_text(c["claim"], cited(c["fact_ids"], where), fixed, where, problems)
    for k, e in enumerate(report.get("possible_explanations", []), 1):
        where = f"possible_explanations[{k}]"
        for a in e["attack_ids"]:
            if a not in candidates:
                problems.append({"where": where, "kind": "attack_id_not_in_candidates", "value": a})
        for a in ATTACK_ID.findall(e["explanation"]):
            if a not in candidates:
                problems.append({"where": where, "kind": "attack_id_not_in_candidates", "value": a})
        check_text(e["explanation"], cited(e["fact_ids"], where), fixed, where, problems)
    s = report["send_recommendation"]
    check_text(s["reason"], cited(s["fact_ids"], "send_recommendation"), fixed, "send_recommendation", problems)
    # 사실 ID가 없는 필드: 숫자가 사실 목록 어딘가에 있는지만 본다
    check_text(report["observation_summary"], facts, fixed, "observation_summary", problems, strong=False)
    for field in ("limitations", "follow_up"):
        for k, t in enumerate(report[field], 1):
            check_text(t, facts, fixed, f"{field}[{k}]", problems, strong=False)
    return problems


def call_llm(client, config, system_prompt, llm_input):
    """구조화 출력 호출 1회(일시 오류만 config["retries"]번 다시). 반환: 호출 기록(성공하면 report 포함)."""
    from google.genai import types

    payload = json.dumps(llm_input, ensure_ascii=False)
    record = {"model": config["model"], "model_version": None, "seconds": None, "usage": None,
              "attempts": 0, "error": None, "report": None}
    t0 = time.time()
    for attempt in range(config["retries"] + 1):
        record["attempts"] = attempt + 1
        try:
            resp = client.models.generate_content(
                model=config["model"], contents=payload,
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt, response_mime_type="application/json",
                    response_json_schema=SCHEMA, temperature=config["temperature"]))
            record["model_version"] = resp.model_version
            u = resp.usage_metadata
            record["usage"] = {"input": u.prompt_token_count, "output": u.candidates_token_count,
                               "thinking": u.thoughts_token_count}
            record["report"] = json.loads(resp.text)  # 형식 오류면 ValueError
            record["error"] = None
            break
        except ValueError as e:  # 형식 오류는 다시 부르지 않는다(1회 보고서)
            record["error"] = f"format: {type(e).__name__}"
            break
        except Exception as e:  # 네트워크·한도·시간 초과. 오류 문장에 입력이 섞일 수 있어 종류만 남긴다
            record["error"] = f"call: {type(e).__name__}"
            if attempt < config["retries"]:
                time.sleep(5)
    record["seconds"] = round(time.time() - t0, 2)
    return record


def final_report(call, llm_input, template):
    """호출 기록 → (화면에 쓸 보고서, 종류, 검증 결과)."""
    if call["report"] is None:
        return template, "template", {"passed": False, "reason": call["error"], "problems": []}
    problems = verify_report(call["report"], llm_input)
    if problems:
        return template, "template", {"passed": False, "reason": "verification", "problems": problems}
    return {"report_version": REPORT_VERSION, **call["report"]}, "llm", {"passed": True, "reason": None,
                                                                         "problems": []}
