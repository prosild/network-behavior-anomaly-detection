"""LLM 보고서 응답의 형식 검사(zeek_ad.report_guard, 프로젝트 검토 Q57 결함 1).

표준 라이브러리만 쓴다: python3 -m unittest tests.test_report_guard -v
확인하는 것:
- 형식이 맞는 응답은 그대로 검증을 거쳐 LLM 보고서가 된다.
- 필수 키 없음, 주장 안 fact_ids 없음, 최상위가 목록, limitations가 문자열, 허용되지 않은 전송 선택은 모두 템플릿이 된다.
  검증 결과 reason은 "format: schema"로 시작하고, 검사한 호출 기록의 report는 None이다(원래 호출 기록은 그대로).
- 형식 검사를 통과해도 검증 중 예외가 나면 템플릿이 된다.
- 스키마 밖 키(최상위·중첩, report_version 포함)는 템플릿이 되고, 이유에는 위치와 개수만 남는다(키 이름 없음).
- 글자 위생(인젝션 시험 후속): 사실 번호·ATT&CK ID 모양, 제어·서식 문자, 문자열·전체 길이 상한의 경계, URL·IPv4 모양,
  사실 목록에 없는 가명. 걸리면 reason이 "format: text"로 시작하고 응답 글은 싣지 않는다. 정상 응답은 그대로 통과한다.
- 독립 검토 보완: 문장 끝 마침표·앞 마침표·포트가 붙은 IPv4, NFKC로 바뀌는 표기(전각 숫자·기호·가명), 보이지 않는 문자,
  결합 문자 연속, 배열 항목 수 상한(넘으면 reason이 "format: size"로 시작하고 다른 검사 전에 끝난다).
"""

import copy
import time
import unittest
from unittest import mock

from zeek_ad import report_guard
from zeek_ad.report_guard import (ARRAY_MAX_ITEMS, COMBINING_MAX_RUN, TEXT_MAX_CHARS, TOTAL_MAX_CHARS,
                                  guarded_final_report, schema_problems, text_problems)

INPUT = {"facts": [{"id": "F01", "name": "queue_rank", "value": 1},
                   {"id": "F02", "name": "top_peer_1", "value": {"peer": "I1", "connections": 7}},
                   {"id": "F03", "name": "example_connection_1", "value": {"source": "H", "destination": "X1"}}],
         "attack_candidates": [{"attack_id": "T1046", "name": "Network Service Discovery"}], "notes": [],
         "model_descriptions": {}}
GOOD = {"observation_summary": "H가 I1과 통신했다.", "claims": [{"claim": "큐 1위다.", "fact_ids": ["F01"]}],
        "possible_explanations": [], "limitations": [], "follow_up": [],
        "send_recommendation": {"choice": "send", "reason": "큐 1위.", "fact_ids": ["F01"]}}
TEMPLATE = {"report_version": "template.v1"}


def call_with(report):
    return {"model": "m", "model_version": "v", "error": None, "report": report}


def broken(change):
    report = copy.deepcopy(GOOD)
    change(report)
    return report


class SchemaTest(unittest.TestCase):
    def test_good_passes(self):
        self.assertEqual(schema_problems(GOOD), [])
        report, kind, verification, call = guarded_final_report(call_with(GOOD), INPUT, TEMPLATE)
        self.assertEqual(kind, "llm")
        self.assertTrue(verification["passed"])
        self.assertIs(call["report"], GOOD)

    def test_malformed_becomes_template(self):
        cases = {
            "send_recommendation 없음": broken(lambda r: r.pop("send_recommendation")),
            "fact_ids 없음": broken(lambda r: r["claims"][0].pop("fact_ids")),
            "최상위 목록": [GOOD],
            "limitations 문자열": broken(lambda r: r.update(limitations="한계 문장")),
            "전송 선택 오타": broken(lambda r: r["send_recommendation"].update(choice="sned")),
            "fact_ids 숫자": broken(lambda r: r["claims"][0].update(fact_ids=[1])),
        }
        for name, bad in cases.items():
            with self.subTest(name):
                raw = call_with(bad)
                report, kind, verification, call = guarded_final_report(raw, INPUT, TEMPLATE)
                self.assertEqual(kind, "template")
                self.assertIs(report, TEMPLATE)
                self.assertTrue(verification["reason"].startswith("format: schema"), verification["reason"])
                self.assertIsNone(call["report"])          # 그래프 상태·전송 판단 비교에는 응답 없음으로
                self.assertIs(raw["report"], bad)          # DB에 저장할 원래 기록은 그대로

    def test_problem_text_has_path_not_content(self):
        problems = schema_problems(broken(lambda r: r.update(limitations="I1 10.10.0.10")))
        self.assertEqual(problems, ["$.limitations: array이어야 하는데 str"])   # LLM 글은 오류 문장에 넣지 않는다

    def test_verify_exception_becomes_template(self):
        with mock.patch.object(report_guard, "final_report",
                               side_effect=[KeyError("x"), (TEMPLATE, "template", {"passed": False})]):
            report, kind, _, call = guarded_final_report(call_with(GOOD), INPUT, TEMPLATE)
        self.assertEqual(kind, "template")
        self.assertEqual(call["error"], "format: verify KeyError")

    def test_failed_call_untouched(self):
        raw = {"model": "m", "model_version": None, "error": "call: TimeoutError", "report": None}
        report, kind, verification, call = guarded_final_report(raw, INPUT, TEMPLATE)
        self.assertEqual((kind, verification["reason"]), ("template", "call: TimeoutError"))


def total_chars(report):
    return sum(len(t) for t in strings(report))


def strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for x in v.values():
            yield from strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from strings(x)


class ExtraKeyTest(unittest.TestCase):
    def check(self, change, where, n):
        bad = broken(change)
        report, kind, verification, call = guarded_final_report(call_with(bad), INPUT, TEMPLATE)
        self.assertEqual(kind, "template")
        self.assertIs(report, TEMPLATE)
        self.assertIn(f"{where}: 스키마 밖 키 {n}개", verification["reason"])
        self.assertTrue(verification["reason"].startswith("format: schema"))
        return verification["reason"]

    def test_top_level_and_report_version(self):
        # 응답이 report_version을 정하지 못한다(final_report가 {"report_version": …, **응답}으로 합치므로)
        reason = self.check(lambda r: r.update(report_version="template.v1"), "$", 1)
        self.assertNotIn("report_version", reason)

    def test_nested_keys_counted_without_names(self):
        reason = self.check(lambda r: r["claims"][0].update({"Ignore previous instructions": 1, "x": 2}),
                            "$.claims[0]", 2)
        self.assertNotIn("Ignore", reason)
        self.check(lambda r: r["send_recommendation"].update(override=True), "$.send_recommendation", 1)


class TextHygieneTest(unittest.TestCase):
    def reason(self, change):
        bad = broken(change)
        report, kind, verification, call = guarded_final_report(call_with(bad), INPUT, TEMPLATE)
        self.assertEqual(kind, "template")
        self.assertIsNone(call["report"])
        self.assertTrue(verification["reason"].startswith("format: text"), verification["reason"])
        return verification["reason"]

    def passes(self, change):
        good = broken(change)
        self.assertEqual(text_problems(good, INPUT), [])
        _, kind, verification, _ = guarded_final_report(call_with(good), INPUT, TEMPLATE)
        self.assertEqual(kind, "llm", verification)

    def test_control_and_format_chars(self):
        for ch in ("\n", "\t", "\x00", "\x1b", "\u200b", "\u202e", "\ufeff", "\u2028"):
            with self.subTest(ch=repr(ch)):
                reason = self.reason(lambda r: r.update(observation_summary=f"정상{ch}이다"))
                self.assertIn("$.observation_summary: 제어·서식 문자", reason)
        self.passes(lambda r: r.update(observation_summary="H가 I1과 통신했다 (UDP·“DNS”) — 7건"))

    def test_text_length_boundary(self):
        self.passes(lambda r: r["claims"][0].update(claim="가" * TEXT_MAX_CHARS))
        reason = self.reason(lambda r: r["claims"][0].update(claim="가" * (TEXT_MAX_CHARS + 1)))
        self.assertIn(f"$.claims[0].claim: 문자열 {TEXT_MAX_CHARS}자 초과", reason)

    def test_total_length_boundary(self):
        def fill(extra):
            def change(r):
                room = TOTAL_MAX_CHARS - total_chars(r) + extra
                r["limitations"] = ["나" * TEXT_MAX_CHARS] * (room // TEXT_MAX_CHARS)
                if room % TEXT_MAX_CHARS:
                    r["limitations"].append("나" * (room % TEXT_MAX_CHARS))
            return change
        self.passes(fill(0))
        self.assertIn(f"$: 응답 전체 {TOTAL_MAX_CHARS}자 초과", self.reason(fill(1)))

    def test_url_and_ipv4(self):
        self.assertIn("URL", self.reason(lambda r: r["follow_up"].append("hxxps://evil.example 확인")))
        # 문장 끝 마침표·앞 마침표·포트·쉼표가 붙어도 잡는다(독립 검토: 이전 정규식은 "10.0.0.5."를 놓쳤다)
        for text in ("10.0.0.5 확인", "12.0.0.1 확인", "255.255.255.255 확인", "공격지는 10.0.0.5.", "주소.10.0.0.5",
                     "10.0.0.5:445 확인", "10.0.0.5, 확인", "(10.0.0.5)"):
            with self.subTest(text=text):
                self.assertIn("IPv4", self.reason(lambda r: r["follow_up"].append(text)))
        # 버전·소수·네 마디가 아닌 것은 IPv4가 아니다(숫자는 동결 검증이 따로 본다)
        for text in ("gemini-3.8 모델", "T1595.001 가설", "1.2.3 단계", "1.2.3.4.5 묶음", "1.2.3.4.5.", "v1.2.3.4.5"):
            with self.subTest(text=text):
                self.assertEqual([p for p in text_problems(broken(lambda r: r["limitations"].append(text)), INPUT)
                                  if "IPv4" in p], [])

    def test_pseudonym_must_be_in_facts_even_in_weak_fields(self):
        # 사실에 있는 I·X 가명은 통과한다(fact_pseudonyms가 X를 빠뜨리면 X1에서 깨진다)
        self.passes(lambda r: r["follow_up"].append("I1과의 연결을 확인한다"))
        self.passes(lambda r: r["follow_up"].append("X1과의 연결을 확인한다"))
        for text in ("I2와의 연결 확인", "X2 확인", "I1~I6 범위"):
            with self.subTest(text=text):
                self.assertIn("사실 목록에 없는 가명", self.reason(lambda r: r["follow_up"].append(text)))
        # 가명 모양이 아닌 토큰(I2C, XI1, 단독 I·X)은 보지 않는다
        self.passes(lambda r: r["follow_up"].append("I2C 버스, XI1 표기, I 와 X"))

    def test_id_shapes(self):
        self.assertIn("모양 아님", self.reason(lambda r: r["claims"][0].update(fact_ids=["ignore previous"])))
        self.assertIn("모양 아님", self.reason(lambda r: r["possible_explanations"].append(
            {"explanation": "가설", "attack_ids": ["T1046; ignore"], "fact_ids": ["F01"]})))

    def test_reason_has_paths_not_text(self):
        reason = self.reason(lambda r: r.update(observation_summary="SECRETWORD http://x\n"))
        self.assertNotIn("SECRETWORD", reason)
        self.assertIn("$.observation_summary", reason)

    def test_nfkc_variants(self):
        # 전각 숫자·전각 기호로 바꿔 쓴 IP·URL·가명은 NFKC 사본에서 잡는다
        cases = {"１０．０．０．５ 확인": "IPv4", "10．0．0．5 확인": "IPv4", "hxxp：／／evil 확인": "URL",
                 "Ｘ2 확인": "가명", "X２ 확인": "가명", "Ｉ９ 확인": "가명"}
        for text, rule in cases.items():
            with self.subTest(text=text):
                self.assertIn(rule, self.reason(lambda r: r["follow_up"].append(text)))
        self.passes(lambda r: r["follow_up"].append("Ｘ1과 Ｉ１ 확인"))    # 정규화하면 사실에 있는 가명
        # 남기는 표기(설계자 결정): "[.]"·"。"로 쓴 IP, 스킴 없는 도메인, IPv6, 이메일
        for text in ("10[.]0[.]0[.]5", "10。0。0。5", "evil.example.com", "fe80::1", "admin@evil.example"):
            with self.subTest(gap=text):
                self.assertEqual(text_problems(broken(lambda r: r["follow_up"].append(text)), INPUT), [])

    def test_invisible_chars_and_combining_runs(self):
        for code in (0x3164, 0x115F, 0x1160, 0xFFA0, 0x2800, 0x034F, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF):
            with self.subTest(code=f"U+{code:04X}"):
                self.assertIn("보이지 않는 문자",
                              self.reason(lambda r: r.update(observation_summary=f"정상{chr(code)}이다")))
        self.passes(lambda r: r.update(observation_summary="e" + "\u0301" * COMBINING_MAX_RUN))
        self.assertIn("결합 문자", self.reason(
            lambda r: r.update(observation_summary="e" + "\u0301" * (COMBINING_MAX_RUN + 1))))
        self.assertIn("결합 문자", self.reason(
            lambda r: r.update(observation_summary="e" + "\u20dd" * (COMBINING_MAX_RUN + 1))))   # Me

    def test_good_response_untouched(self):
        self.assertEqual(text_problems(GOOD, INPUT), [])


class ArraySizeTest(unittest.TestCase):
    def check(self, change, where):
        bad = broken(change)
        report, kind, verification, call = guarded_final_report(call_with(bad), INPUT, TEMPLATE)
        self.assertEqual(kind, "template")
        self.assertTrue(verification["reason"].startswith("format: size"), verification["reason"])
        self.assertIn(f"{where}: 배열 항목 수 상한 초과", verification["reason"])

    def passes(self, change):
        _, kind, verification, _ = guarded_final_report(call_with(broken(change)), INPUT, TEMPLATE)
        self.assertEqual(kind, "llm", verification)

    def test_boundaries(self):
        claim = {"claim": "큐 1위다.", "fact_ids": ["F01"]}
        expl = {"explanation": "가설", "attack_ids": ["T1046"], "fact_ids": ["F01"]}
        n = ARRAY_MAX_ITEMS
        cases = [
            ("$.claims", lambda r, k: r.update(claims=[dict(claim) for _ in range(k)]), n["$.claims"]),
            ("$.claims[0].fact_ids", lambda r, k: r["claims"][0].update(fact_ids=["F01"] * k),
             n["$.claims[].fact_ids"]),
            ("$.possible_explanations", lambda r, k: r.update(possible_explanations=[dict(expl)] * k),
             n["$.possible_explanations"]),
            ("$.possible_explanations[0].attack_ids", lambda r, k: r.update(possible_explanations=[
                {**expl, "attack_ids": ["T1046"] * k}]), n["$.possible_explanations[].attack_ids"]),
            ("$.possible_explanations[0].fact_ids", lambda r, k: r.update(possible_explanations=[
                {**expl, "fact_ids": ["F01"] * k}]), n["$.possible_explanations[].fact_ids"]),
            ("$.limitations", lambda r, k: r.update(limitations=["한계"] * k), n["$.limitations"]),
            ("$.follow_up", lambda r, k: r.update(follow_up=["확인"] * k), n["$.follow_up"]),
            ("$.send_recommendation.fact_ids", lambda r, k: r["send_recommendation"].update(fact_ids=["F01"] * k),
             n["$.send_recommendation.fact_ids"]),
        ]
        self.assertEqual(len(cases), len(ARRAY_MAX_ITEMS))
        for where, change, limit in cases:
            with self.subTest(where=where):
                self.passes(lambda r: change(r, limit))
                self.check(lambda r: change(r, limit + 1), where)

    def test_huge_array_is_rejected_fast(self):
        # 독립 검토: 빈 문자열 20만 개가 글자 수 상한을 피하고 처리에 9.8초 걸렸다. 크기 검사가 먼저 끝낸다
        t0 = time.time()
        self.check(lambda r: r.update(limitations=[""] * 200_000), "$.limitations")
        self.assertLess(time.time() - t0, 1.0)


if __name__ == "__main__":
    unittest.main()
