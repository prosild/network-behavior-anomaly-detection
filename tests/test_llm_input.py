"""LLM 입력 만들기(zeek_ad.llm_input) 시험. 표준 라이브러리만 쓴다.

실행: python3 -m unittest tests.test_llm_input -v
"""

import json
import re
import unittest

from zeek_ad.llm_input import (Pseudonyms, baseline_facts, build_facts, fact_map, percentile, query_sentence,
                               template_report)

NETS = ["192.168.10.0/24"]


def evidence(**over):
    """작은 가짜 근거(evidence.v1 모양)."""
    ev = {
        "version": "evidence.v1", "host": {"ip": "192.168.10.50"}, "zeekad_role": "responder",
        "event": {"start": "2017-07-05T13:45:00Z", "end": "2017-07-05T14:15:00Z"},
        "connection_count": 100,
        "network": {"transport": {"tcp": 100}, "protocol": {"http": 90, "evil<script>": 10},
                    "bytes": {"sent": 5000, "received": 100}, "zeekad_payload_bytes_inflated": 0},
        "zeek_conn_state": {"RSTO": 60, "SF": 40},
        "peers": {"unique": 2, "top": [{"ip": "172.16.0.1", "connections": 95},
                                       {"ip": "192.168.10.25", "connections": 5}]},
        "destination_ports": {"unique": 1, "top": [{"port": 80, "transport": "tcp", "connections": 100}]},
        "protocol_logs": {"http": {"requests": 90, "errors": 0}, "dns": {"max_query_length": 72},
                          "smb": {"mappings": 2, "files": 0},
                          "dce_rpc": {"calls": 2, "top_operations": [{"operation": "NetrShareEnum", "connections": 2},
                                                                     {"operation": "drop table;", "connections": 1}]}},
        "representative_connections": [
            {"zeek": {"uid": "CiQcQl2qxnMgafJIJc", "conn_state": "SF"},
             "event": {"start": "2017-07-05T13:43:23Z", "duration": 0.5},
             "source": {"ip": "172.16.0.1", "port": 52974, "bytes": 704},
             "destination": {"ip": "192.168.10.50", "port": 80, "bytes": 11915},
             "network": {"transport": "tcp", "protocol": "http"}}],
        "limits": [],
    }
    ev.update(over)
    return ev


INCIDENT = {"queue_rank": 3, "picked_by": "tgn_recon", "also_flagged_by": ["tail_rarity_v2"]}
WINDOWS = {"tgn_recon": (4, 6), "transformer_v2": (0, 6)}


class PseudonymTest(unittest.TestCase):
    def test_same_ip_same_name_and_zone(self):
        p = Pseudonyms("192.168.10.50", NETS)
        self.assertEqual(p("192.168.10.50"), "H")
        self.assertEqual(p("172.16.0.1"), "X1")
        self.assertEqual(p("192.168.10.3"), "I1")
        self.assertEqual(p("8.8.8.8"), "X2")
        self.assertEqual(p("172.16.0.1"), "X1")


class FactsTest(unittest.TestCase):
    def setUp(self):
        self.facts = build_facts(evidence(), INCIDENT, WINDOWS, NETS)
        self.text = json.dumps(self.facts)

    def test_no_ip_date_or_uid(self):
        self.assertIsNone(re.search(r"\d+\.\d+\.\d+\.\d+", self.text))
        self.assertIsNone(re.search(r"20\d\d-\d\d-\d\d", self.text))
        self.assertNotIn("CiQcQl2qxnMgafJIJc", self.text)

    def test_unknown_strings_become_other(self):
        self.assertNotIn("script", self.text)
        self.assertNotIn("drop table", self.text)
        m = fact_map(self.facts)
        self.assertIn("protocol.other", m)
        self.assertEqual(m["dce_rpc.top_operation_2"]["value"]["operation"], "other")

    def test_relative_time_and_ids(self):
        m = fact_map(self.facts)
        self.assertEqual(m["incident_duration_seconds"]["value"], 1800)
        self.assertEqual(m["example_connection_1"]["value"]["start_seconds"], -97.0)
        self.assertEqual(m["example_connection_1"]["value"]["source"], "X1")
        ids = [f["id"] for f in self.facts]
        self.assertEqual(len(ids), len(set(ids)))

    def test_model_opinions(self):
        m = fact_map(self.facts)
        self.assertEqual(m["model_candidate_windows.tgn_recon"]["value"], {"candidate": 4, "windows": 6})
        self.assertEqual(m["also_flagged_by_models"]["value"], ["tail_rarity_v2"])


class BaselineTest(unittest.TestCase):
    def test_percentile_matches_linear_interpolation(self):
        # pandas Series([1, 2, 3, 10]).quantile(0.95) == 8.95
        self.assertAlmostEqual(percentile([10, 1, 3, 2], 0.95), 8.95)
        self.assertEqual(percentile([5], 0.5), 5)
        self.assertIsNone(percentile([], 0.5))

    def test_incident_next_to_monday(self):
        inc = [{"conn_count": 46675.0, "dns_query_count": 0.0, "http_request_count": 900.0}]
        base = [{"conn_count": float(c), "dns_query_count": 0.0, "http_request_count": 0.0} for c in (10, 20, 30)]
        m = dict(baseline_facts(inc, base))
        self.assertEqual(m["baseline_windows"], {"incident_windows": 1, "baseline_windows": 3})
        self.assertEqual(m["baseline.connections_per_window"],
                         {"incident_max": 46675, "baseline_p50": 20, "baseline_p95": 29, "baseline_max": 30})
        self.assertIn("baseline.http_requests_per_window", m)   # 사건에서 0보다 크다
        self.assertNotIn("baseline.dns_queries_per_window", m)  # 사건·기준 모두 0이라 뺀다

    def test_missing_values_and_empty_baseline(self):
        m = dict(baseline_facts([{"out_bytes_sum": None}], []))
        self.assertEqual(m["baseline.payload_bytes_sent_by_host_per_window"],
                         {"incident_max": None, "baseline_p50": None, "baseline_p95": None, "baseline_max": None})

    def test_baseline_and_units_in_facts(self):
        base = baseline_facts([{"conn_count": 5.0}], [{"conn_count": 4.0}])
        m = fact_map(build_facts(evidence(), INCIDENT, WINDOWS, NETS, baseline=base))
        self.assertIn("baseline.connections_per_window", m)
        self.assertEqual(m["dns.max_query_length_chars"]["value"], 72)
        self.assertNotIn("dns.max_query_length", m)


class QueryTest(unittest.TestCase):
    def test_behavior_sentence(self):
        q = query_sentence(build_facts(evidence(), INCIDENT, WINDOWS, NETS))
        self.assertIn("mostly an external peer", q)
        self.assertIn("mostly HTTP traffic", q)
        self.assertIn("many connections reset", q)
        self.assertNotIn("SMB", q)  # 연결의 2%라 행동으로 쓰지 않는다

    def test_icmp_is_not_a_port(self):
        ev = evidence(destination_ports={"unique": 1, "top": [{"port": 10, "transport": "icmp", "connections": 1}]})
        q = query_sentence(build_facts(ev, INCIDENT, WINDOWS, NETS))
        self.assertIn("ICMP messages", q)
        self.assertNotIn("port 10", q)


class TemplateTest(unittest.TestCase):
    def test_claims_reference_existing_facts(self):
        facts = build_facts(evidence(), INCIDENT, WINDOWS, NETS)
        report = template_report(facts, [{"attack_id": "T1499.002", "name": "Service Exhaustion Flood"}])
        ids = {f["id"] for f in facts}
        for c in report["claims"]:
            self.assertTrue(set(c["fact_ids"]) <= ids)
        self.assertIn("T1499.002", report["possible_explanations"][0])
        # 화면에 보이는 한계 문장은 한국어다
        self.assertTrue(all(any("가" <= ch <= "힣" for ch in line) for line in report["limitations"]))


if __name__ == "__main__":
    unittest.main()
