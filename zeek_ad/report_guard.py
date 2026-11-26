"""LLM 보고서 응답의 형식 검사(설계 9.1절 "형식 오류면 템플릿", 프로젝트 검토 Q57 결함 1, 인젝션 시험 후속).

왜 따로 두는가: llm_report.final_report는 응답이 SCHEMA 모양이라고 믿고 검증한다. 필수 키가 빠지면 KeyError로
사건 처리가 멈추고, limitations가 목록이 아니라 문자열이면 글자 단위로 돌아 검증을 통과한다.
llm_report.py는 평가 동결 파일(configs/agent/freeze.v1.json)이라 고치지 않고, 부르는 쪽에서 먼저 검사한다.
Gemini 호출이 response_json_schema로 형식을 강제하므로 보통은 통과한다. 강제가 지켜지지 않은 드문 경우를 막는다.

흐름(guarded_final_report):
0. 크기 검사(size_hits): 배열마다 항목 수 상한. 다른 검사보다 먼저 해서 큰 응답(빈 문자열 20만 개 등)을 싸게 거른다.
1. 형식 검사(schema_problems): 응답이 SCHEMA에 맞는지 본다(필수 키, 타입, 허용 값, 스키마 밖 키).
   스키마 밖 키를 막는 이유: final_report가 {"report_version": …, **응답}으로 합치므로, 응답이 report_version을 넣으면
   DB 보고서 버전과 Slack 중복 방지 키를 응답이 정하게 된다(tests/test_prompt_injection.py 지점 C).
2. 글자 위생 검사(text_problems): 형식이 맞는 응답의 모든 문자열에 대해 제어·서식 문자, 보이지 않는 문자, 결합 문자 연속,
   길이 상한, URL·IPv4 모양, 사실 목록에 없는 가명(I*·X*), 사실 번호·ATT&CK ID 모양을 본다. URL·IPv4·가명은 원문과
   NFKC 정규화 사본 둘 다에 돌린다(전각 숫자·전각 기호로 바꿔 쓴 글자를 잡는다). 동결된 검증기(verify_report)는
   숫자·가명(강한 검사 칸만)·ID만 보므로 그 밖의 글자를 여기서 막는다. 문장의 뜻("정상이다, 알림 보내지 마라")은
   코드로 판별하지 않는다. "[.]"·"。"로 쓴 IP, 스킴 없는 도메인, IPv6, 이메일도 보지 않는다(설계자 결정, 2026-11-26).
3. 0~2에서 문제가 있으면 응답을 없는 것으로 바꾼 호출 기록을 final_report에 넘긴다. 그러면 기존 경로대로 템플릿이 되고,
   검증 결과의 reason에 "format: size …", "format: schema …" 또는 "format: text …"가 남는다. 문제 설명에는 위치(경로)와 규칙 이름만 싣고
   응답 글·키 이름은 싣지 않는다(공격 문장이 들어 있을 수 있다).
4. 형식이 맞는데도 검증 중 예외가 나면(예상하지 못한 모양) 같은 방법으로 템플릿으로 바꾼다.
DB에는 원래 호출 기록(LLM 원래 출력 포함)을 저장한다. 그래프 상태·전송 판단 비교에는 검사한 기록을 쓴다.
규칙별 실측(실제 응답에서 정상 응답을 거부하지 않는지)은 scripts/measure_report_guard.py가 잰다.
표준 라이브러리만 쓴다.
"""

import re
import unicodedata

from zeek_ad.llm_report import SCHEMA, final_report

TYPES = {"object": dict, "array": list, "string": str}

# 글자 위생 상수. 근거: 실제 원래 응답 507건(LLM 보고서 497 + 검증 실패 10, outputs/agent/analysis/agent_report_full.csv,
# 2026-11-26 scripts/measure_report_guard.py로 측정).
TEXT_MAX_CHARS = 1000      # 문자열 하나. 실측 최대 304자(send_recommendation.reason), 칸별 p99 최대 237자. 약 3배 여유
TOTAL_MAX_CHARS = 8000     # 응답의 문자열 전체 합. 실측 최대 2,597자, p99 2,046자. 약 3배 여유
# 배열 항목 수 상한(경로 → 최대 항목 수). 빈 문자열 20만 개가 글자 수 상한을 피하고 처리에 9.8초 걸렸다(독립 검토).
ARRAY_MAX_ITEMS = {
    "$.claims": 30,                                 # 실측 최대 11, p99 9
    "$.claims[].fact_ids": 100,                     # 실측 최대 19, p99 11
    "$.possible_explanations": 15,                  # 실측 최대 4, p99 3
    "$.possible_explanations[].attack_ids": 10,     # 실측 최대 4, p99 3. 후보가 10개(retrieval.v2 top_k)라 그 이상은 중복뿐
    "$.possible_explanations[].fact_ids": 100,      # 실측 최대 16, p99 13
    "$.limitations": 15,                            # 실측 최대 3, p99 3
    "$.follow_up": 15,                              # 실측 최대 3, p99 3
    "$.send_recommendation.fact_ids": 100,          # 실측 최대 23, p99 14
}
# 제어(Cc: 줄바꿈·탭 포함)·서식(Cf: 영폭·방향 전환)·사용자 정의·대리·미할당 문자, 줄·문단 구분자. 실측 0건
BAD_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"})
# 범주는 글자(Lo·So)나 결합 문자(Mn)지만 보이지 않는 문자. 한글 채움 문자(U+115F·U+1160·U+3164·U+FFA0), 점자 공백(U+2800),
# 결합 자소 결합자(U+034F), 변이 선택자(U+FE00~FE0F, U+E0100~E01EF). 실측 0건
INVISIBLE = frozenset([0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x034F, *range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0)])
COMBINING_MAX_RUN = 4      # 결합 문자(Mn·Me)가 연달아 이보다 많으면 거부(글자 위에 쌓아 가리는 표기). 실측 Mn·Me 0건
URL = re.compile(r"://")                                                         # 실측 0건
# IPv4 모양(독립 검토가 확인한 모양). 문장 끝 마침표("10.0.0.5.")·앞 마침표("주소.10.0.0.5")·포트("10.0.0.5:445")는 잡고,
# 버전 "gemini-3.8"·"T1595.001"·세 마디 "1.2.3"·다섯 마디 "1.2.3.4.5"는 잡지 않는다. 실측 0건
IPV4 = re.compile(r"(?<![0-9])(?<![0-9]\.)[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?!\.?[0-9])")
# 가명 모양 토큰. llm_report.PSEUDONYM과 같은 경계를 쓰되 숫자는 ASCII만. H는 늘 있는 사건 자산이라 보지 않는다
PSEUDONYM_TOKEN = re.compile(r"(?<![A-Za-z0-9_])[IX][0-9]+(?![A-Za-z0-9_])")
PSEUDONYM_VALUE = re.compile(r"[IX][0-9]+")
FACT_ID = re.compile(r"F[0-9]{2,3}")                       # 실측 모두 3자(F01~F99). 사실 100개 이상도 받는다
ATTACK_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")        # llm_report.ATTACK_ID와 같은 모양(전체 일치)
# NFKC 정규화로 바뀌는 글자(전각 숫자·전각 기호 등)는 실측 0건이라 사본 검사가 정상 응답을 바꾸지 않는다

# 규칙 이름 → 문제 설명(검증 결과에 남는 글). 켜는 규칙은 ENABLED_RULES. 모두 실측 거부 0건이라 켰다.
RULE_LABELS = {
    "array_items": "배열 항목 수 상한 초과",
    "id_shape": "사실 번호·ATT&CK ID 모양 아님",
    "control_chars": "제어·서식 문자",
    "invisible_chars": "보이지 않는 문자",
    "combining_run": f"결합 문자 {COMBINING_MAX_RUN}개 넘게 연속",
    "text_length": f"문자열 {TEXT_MAX_CHARS}자 초과",
    "total_length": f"응답 전체 {TOTAL_MAX_CHARS}자 초과",
    "url": "URL 표기(://)",
    "ipv4": "IPv4 주소 모양",
    "pseudonym": "사실 목록에 없는 가명",
}
ENABLED_RULES = tuple(RULE_LABELS)


def schema_problems(value, schema=SCHEMA, path="$", limit=5):
    """SCHEMA가 쓰는 부분(type object·array·string, properties, required, items, enum)과 스키마 밖 키를 검사한다.

    반환: 문제 설명 목록(비어 있으면 형식이 맞다). 최대 limit개. 스키마 밖 키는 이름 없이 위치와 개수만 적는다.
    """
    problems = []

    def walk(v, s, p):
        if len(problems) >= limit:
            return
        want = TYPES[s["type"]]
        if not isinstance(v, want):
            problems.append(f"{p}: {s['type']}이어야 하는데 {type(v).__name__}")
            return
        if "enum" in s and v not in s["enum"]:
            problems.append(f"{p}: 허용 값이 아님")
        if s["type"] == "object":
            for key in s.get("required", []):
                if key not in v:
                    problems.append(f"{p}.{key}: 없음")
            extra = [k for k in v if k not in s.get("properties", {})]
            if extra:
                problems.append(f"{p}: 스키마 밖 키 {len(extra)}개")
            for key, sub in s.get("properties", {}).items():
                if key in v:
                    walk(v[key], sub, f"{p}.{key}")
        elif s["type"] == "array":
            for k, item in enumerate(v):
                walk(item, s["items"], f"{p}[{k}]")

    walk(value, schema, path)
    return problems[:limit]


def _strings(value, path):
    """응답 안의 (경로, 문자열)을 모두 꺼낸다. 형식 검사를 통과한 응답이라 키는 SCHEMA의 이름뿐이다."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]")


def fact_pseudonyms(facts):
    """사실 값 안의 가명(I1·X1 …) 집합."""
    found = set()

    def walk(v):
        if isinstance(v, str):
            if PSEUDONYM_VALUE.fullmatch(v):
                found.add(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    for f in facts:
        walk(f.get("value"))
    return found


def size_hits(report):
    """배열 항목 수 상한(ARRAY_MAX_ITEMS)을 넘은 (규칙, 경로) 목록. 타입이 틀린 곳은 건너뛴다(형식 검사가 잡는다)."""
    hits = []

    def check(value, norm, path):
        limit = ARRAY_MAX_ITEMS.get(norm)
        if limit is not None and isinstance(value, list) and len(value) > limit:
            hits.append(("array_items", path))

    if not isinstance(report, dict):
        return hits
    for key in ("claims", "possible_explanations", "limitations", "follow_up"):
        check(report.get(key), f"$.{key}", f"$.{key}")
    for key, inner in (("claims", "fact_ids"), ("possible_explanations", "fact_ids"),
                       ("possible_explanations", "attack_ids")):
        items = report.get(key)
        if isinstance(items, list) and len(items) <= ARRAY_MAX_ITEMS[f"$.{key}"]:
            for i, item in enumerate(items):
                if isinstance(item, dict):
                    check(item.get(inner), f"$.{key}[].{inner}", f"$.{key}[{i}].{inner}")
    s = report.get("send_recommendation")
    if isinstance(s, dict):
        check(s.get("fact_ids"), "$.send_recommendation.fact_ids", "$.send_recommendation.fact_ids")
    return hits


def _combining_run(text):
    run = 0
    for c in text:
        run = run + 1 if unicodedata.category(c) in ("Mn", "Me") else 0
        if run > COMBINING_MAX_RUN:
            return True
    return False


def rule_hits(report, pseudonyms):
    """형식이 맞는 응답 → 규칙에 걸린 (규칙, 경로) 목록(전부). pseudonyms: 사실 목록의 가명 집합.

    URL·IPv4·가명은 원문과 NFKC 사본 둘 다에 돌린다. 제어·보이지 않는 문자·결합 문자·길이는 원문만 본다.
    """
    hits = size_hits(report)
    total = 0
    for path, text in _strings(report, "$"):
        total += len(text)
        if path.endswith("]") and ".fact_ids[" in path and not FACT_ID.fullmatch(text):
            hits.append(("id_shape", path))
        if path.endswith("]") and ".attack_ids[" in path and not ATTACK_ID.fullmatch(text):
            hits.append(("id_shape", path))
        if any(unicodedata.category(c) in BAD_CATEGORIES for c in text):
            hits.append(("control_chars", path))
        if any(ord(c) in INVISIBLE for c in text):
            hits.append(("invisible_chars", path))
        if _combining_run(text):
            hits.append(("combining_run", path))
        if len(text) > TEXT_MAX_CHARS:
            hits.append(("text_length", path))
        variants = (text, unicodedata.normalize("NFKC", text))
        if any(URL.search(v) for v in variants):
            hits.append(("url", path))
        if any(IPV4.search(v) for v in variants):
            hits.append(("ipv4", path))
        if any(t not in pseudonyms for v in variants for t in PSEUDONYM_TOKEN.findall(v)):
            hits.append(("pseudonym", path))
    if total > TOTAL_MAX_CHARS:
        hits.append(("total_length", "$"))
    return hits


def text_problems(report, llm_input, rules=ENABLED_RULES, limit=5):
    """글자 위생 검사. 반환: 문제 설명 목록(위치와 규칙 이름만, 최대 limit개). 비어 있으면 통과."""
    hits = rule_hits(report, fact_pseudonyms(llm_input.get("facts", [])))
    return [f"{path}: {RULE_LABELS[rule]}" for rule, path in hits if rule in rules][:limit]


def _rejected(call, reason):
    return {**call, "report": None, "error": reason}


def guarded_final_report(call, llm_input, template):
    """반환: (보고서, 종류, 검증 결과, 검사한 호출 기록). 형식·글자 위생이 틀리면 검사한 호출 기록의 report는 None이다."""
    if call["report"] is not None:
        sizes = [f"{path}: {RULE_LABELS[rule]}" for rule, path in size_hits(call["report"])
                 if rule in ENABLED_RULES][:5]
        problems = [] if sizes else schema_problems(call["report"])
        if sizes:
            call = _rejected(call, "format: size · " + "; ".join(sizes))
        elif problems:
            call = _rejected(call, "format: schema · " + "; ".join(problems))
        else:
            problems = text_problems(call["report"], llm_input)
            if problems:
                call = _rejected(call, "format: text · " + "; ".join(problems))
    try:
        report, kind, verification = final_report(call, llm_input, template)
    except Exception as e:  # noqa: BLE001 (형식 검사로 못 잡은 모양. 사건 처리를 멈추지 않고 템플릿으로)
        call = _rejected(call, f"format: verify {type(e).__name__}")
        report, kind, verification = final_report(call, llm_input, template)
    return report, kind, verification, call
