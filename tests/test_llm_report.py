"""LLM 보고서 검증(zeek_ad.llm_report) 시험. 표준 라이브러리만 쓴다.

실행: python3 -m unittest tests.test_llm_report -v
"""

import copy
import unittest

from zeek_ad.llm_report import final_report, text_numbers, verify_report

LLM_INPUT = {
    "notes": ["Monday windows are 5-minute windows"],
    "model_descriptions": {"transformer_v2": "previous 12 windows (1 hour)"},
    "facts": [
        {"id": "F01", "name": "connection_count", "value": 155261},
        {"id": "F02", "name": "top_peer_1", "value": {"peer": "X1", "connections": 155111}},
        {"id": "F03", "name": "baseline.connections_per_window",
         "value": {"incident_max": 46675, "baseline_p50": 20, "baseline_p95": 31, "baseline_max": 34}},
        {"id": "F04", "name": "unestablished_ratio", "value": 0.125},
        {"id": "F05", "name": "also_flagged_by_models", "value": ["tail_rarity_v2", "transformer_v2"]},
    ],
    "attack_candidates": [{"attack_id": "T1499.002", "name": "Service Exhaustion Flood"}],
}
GOOD = {
    "observation_summary": "연결 155,261건이 관측됐다",
    "claims": [{"claim": "X1이 155111건으로 가장 많다", "fact_ids": ["F02"]},
               {"claim": "창 최대 46675건, 월요일 최대 34건보다 훨씬 많다", "fact_ids": ["F03"]},
               {"claim": "미성립 비율 0.13", "fact_ids": ["F04"]},
               {"claim": "다른 2개 모델도 꼽았다", "fact_ids": ["F05"]}],
    "possible_explanations": [{"explanation": "T1499.002 가설", "attack_ids": ["T1499.002"], "fact_ids": ["F01"]}],
    "limitations": ["5분 창 기준이다"],
    "follow_up": ["대표 연결 확인"],
    "send_recommendation": {"choice": "send", "reason": "월요일 p95 31건보다 크다", "fact_ids": ["F03"]},
}


def kinds(problems):
    return sorted({p["kind"] for p in problems})


class NumberTest(unittest.TestCase):
    def test_identifiers_are_not_numbers(self):
        self.assertEqual([n for _, n in text_numbers("F43 X1 T1595.001 p95 gemini-3.8 80/tcp 1,234건 -97.5초")],
                         [80.0, 1234.0, -97.5])

    def test_terms_are_not_numbers(self):
        self.assertEqual(text_numbers("95백분위수, 50 백분위, 4xx/5xx 응답"), [])


class VerifyTest(unittest.TestCase):
    def test_good_report_passes(self):
        self.assertEqual(verify_report(GOOD, LLM_INPUT), [])

    def bad(self, edit):
        r = copy.deepcopy(GOOD)
        edit(r)
        return kinds(verify_report(r, LLM_INPUT))

    def test_number_must_be_in_cited_fact(self):
        # 155111·X1은 F02에 있지만 F01만 인용했다
        self.assertEqual(self.bad(lambda r: r["claims"][0].update(fact_ids=["F01"])),
                         ["number_not_in_facts", "pseudonym_not_in_facts"])

    def test_computed_numbers_fail(self):
        self.assertEqual(self.bad(lambda r: r["claims"][1].update(claim="월요일보다 1373배 많다")),
                         ["number_not_in_facts"])

    def test_pseudonym_must_be_in_cited_fact(self):
        self.assertEqual(self.bad(lambda r: r["claims"][1].update(claim="X2가 46675건")), ["pseudonym_not_in_facts"])

    def test_unknown_ids(self):
        # 없는 ID만 인용하면 인용한 사실이 비어 X1·155111도 근거가 없다
        self.assertEqual(self.bad(lambda r: r["claims"][0].update(fact_ids=["F99"])),
                         ["number_not_in_facts", "pseudonym_not_in_facts", "unknown_fact_id"])

    def test_attack_id_outside_candidates(self):
        self.assertEqual(self.bad(lambda r: r["possible_explanations"][0].update(attack_ids=["T1046"])),
                         ["attack_id_not_in_candidates"])
        self.assertEqual(self.bad(lambda r: r["possible_explanations"][0].update(explanation="T1046 가설")),
                         ["attack_id_not_in_candidates"])

    def test_weak_fields_check_all_facts(self):
        self.assertEqual(self.bad(lambda r: r["limitations"].append("기준 창 76개")), ["number_not_in_facts"])


class FallbackTest(unittest.TestCase):
    def test_template_on_failure(self):
        tpl = {"report_version": "template.v1"}
        rep, kind, ver = final_report({"report": None, "error": "call: TimeoutError"}, LLM_INPUT, tpl)
        self.assertEqual((rep, kind, ver["reason"]), (tpl, "template", "call: TimeoutError"))
        bad = copy.deepcopy(GOOD)
        bad["claims"][1]["claim"] = "1373배"
        rep, kind, ver = final_report({"report": bad, "error": None}, LLM_INPUT, tpl)
        self.assertEqual((kind, ver["reason"]), ("template", "verification"))
        rep, kind, ver = final_report({"report": GOOD, "error": None}, LLM_INPUT, tpl)
        self.assertEqual((kind, rep["report_version"]), ("llm", "llm-report.v1"))


if __name__ == "__main__":
    unittest.main()
