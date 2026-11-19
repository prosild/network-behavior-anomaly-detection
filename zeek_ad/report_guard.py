"""LLM 보고서 응답의 형식 검사(설계 9.1절 "형식 오류면 템플릿", 프로젝트 검토 Q57 결함 1).

왜 따로 두는가: llm_report.final_report는 응답이 SCHEMA 모양이라고 믿고 검증한다. 필수 키가 빠지면 KeyError로
사건 처리가 멈추고, limitations가 목록이 아니라 문자열이면 글자 단위로 돌아 검증을 통과한다.
llm_report.py는 평가 동결 파일(configs/agent/freeze.v1.json)이라 고치지 않고, 부르는 쪽에서 먼저 검사한다.
Gemini 호출이 response_json_schema로 형식을 강제하므로 보통은 통과한다. 강제가 지켜지지 않은 드문 경우를 막는다.

흐름(guarded_final_report):
1. 응답이 SCHEMA에 맞는지 본다(필수 키, 타입, 허용 값). 맞지 않으면 응답을 없는 것으로 바꾼 호출 기록을
   final_report에 넘긴다. 그러면 기존 경로대로 템플릿이 되고, 검증 결과의 reason에 "format: schema ..."가 남는다.
2. 형식이 맞는데도 검증 중 예외가 나면(예상하지 못한 모양) 같은 방법으로 템플릿으로 바꾼다.
DB에는 원래 호출 기록(LLM 원래 출력 포함)을 저장한다. 그래프 상태·전송 판단 비교에는 검사한 기록을 쓴다.
표준 라이브러리만 쓴다.
"""

from zeek_ad.llm_report import SCHEMA, final_report

TYPES = {"object": dict, "array": list, "string": str}


def schema_problems(value, schema=SCHEMA, path="$", limit=5):
    """SCHEMA가 쓰는 부분(type object·array·string, properties, required, items, enum)만 검사한다.

    반환: 문제 설명 목록(비어 있으면 형식이 맞다). 최대 limit개.
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
            for key, sub in s.get("properties", {}).items():
                if key in v:
                    walk(v[key], sub, f"{p}.{key}")
        elif s["type"] == "array":
            for k, item in enumerate(v):
                walk(item, s["items"], f"{p}[{k}]")

    walk(value, schema, path)
    return problems[:limit]


def _rejected(call, reason):
    return {**call, "report": None, "error": reason}


def guarded_final_report(call, llm_input, template):
    """반환: (보고서, 종류, 검증 결과, 검사한 호출 기록). 형식이 틀리면 검사한 호출 기록의 report는 None이다."""
    if call["report"] is not None:
        problems = schema_problems(call["report"])
        if problems:
            call = _rejected(call, "format: schema · " + "; ".join(problems))
    try:
        report, kind, verification = final_report(call, llm_input, template)
    except Exception as e:  # noqa: BLE001 (형식 검사로 못 잡은 모양. 사건 처리를 멈추지 않고 템플릿으로)
        call = _rejected(call, f"format: verify {type(e).__name__}")
        report, kind, verification = final_report(call, llm_input, template)
    return report, kind, verification, call
