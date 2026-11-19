"""LLM 보고서 응답의 형식 검사(zeek_ad.report_guard, 프로젝트 검토 Q57 결함 1).

표준 라이브러리만 쓴다: python3 -m unittest tests.test_report_guard -v
확인하는 것:
- 형식이 맞는 응답은 그대로 검증을 거쳐 LLM 보고서가 된다.
- 필수 키 없음, 주장 안 fact_ids 없음, 최상위가 목록, limitations가 문자열, 허용되지 않은 전송 선택은 모두 템플릿이 된다.
  검증 결과 reason은 "format: schema"로 시작하고, 검사한 호출 기록의 report는 None이다(원래 호출 기록은 그대로).
- 형식 검사를 통과해도 검증 중 예외가 나면 템플릿이 된다.
"""

import copy
import unittest
from unittest import mock

from zeek_ad import report_guard
from zeek_ad.report_guard import guarded_final_report, schema_problems

INPUT = {"facts": [{"id": "F01", "name": "queue_rank", "value": 1}], "attack_candidates": [], "notes": [],
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


if __name__ == "__main__":
    unittest.main()
