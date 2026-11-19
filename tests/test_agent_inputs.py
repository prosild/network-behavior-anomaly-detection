"""가명표(zeek_ad.agent_inputs.pseudonym_map) 시험.

pseudonym_map은 build_facts(llm_input.py, 평가 동결 파일)가 가명을 매기는 순서를 따라 한다.
여기서는 build_facts 안에서 실제로 만들어진 가명표를 가로채 같은지 비교한다. 순서가 어긋나면(예: llm_input.py가
가명을 매기는 곳을 늘리면) 이 시험이 실패한다.
agent_inputs가 pandas를 쓰므로 zeek-ad 환경에서 실행한다: python -m unittest tests.test_agent_inputs -v
"""

import unittest
from unittest import mock

from zeek_ad import llm_input
from zeek_ad.agent_inputs import pseudonym_map
from tests.test_llm_input import INCIDENT, NETS, WINDOWS, evidence


def connection(src, dst):
    return {"zeek": {"uid": "C1", "conn_state": "S0"}, "event": {"start": "2017-07-05T13:50:00Z", "duration": None},
            "source": {"ip": src, "port": 40000, "bytes": 0}, "destination": {"ip": dst, "port": 445, "bytes": 0},
            "network": {"transport": "tcp", "protocol": None}}


class PseudonymMapTest(unittest.TestCase):
    def real_map(self, ev):
        """build_facts가 쓴 Pseudonyms 객체를 가로채 {가명: IP}로 돌려준다."""
        made = []

        class Capture(llm_input.Pseudonyms):
            def __init__(self, *a):
                super().__init__(*a)
                made.append(self)

        with mock.patch.object(llm_input, "Pseudonyms", Capture):
            facts = llm_input.build_facts(ev, INCIDENT, WINDOWS, NETS)
        return {name: ip for ip, name in made[0].map.items()}, facts

    def test_same_as_build_facts(self):
        # 상위 상대에 없는 IP가 대표 연결에만 나오고, 대표 연결이 상한(5개)을 넘는 경우
        conns = [connection("192.168.10.50", f"192.168.10.{k}") for k in range(100, 107)]
        ev = evidence(representative_connections=evidence()["representative_connections"] + conns)
        real, facts = self.real_map(ev)
        self.assertEqual(pseudonym_map(ev, NETS), real)
        self.assertEqual(real["H"], "192.168.10.50")
        self.assertNotIn("192.168.10.106", real.values())     # 상한 밖 연결의 IP는 사실 목록에 없다

    def test_every_pseudonym_in_facts_is_mapped(self):
        real, facts = self.real_map(evidence())
        text = str([f["value"] for f in facts])
        used = {p for p in ("H", "I1", "I2", "X1", "X2") if f"'{p}'" in text}
        self.assertTrue(used <= set(pseudonym_map(evidence(), NETS)))


if __name__ == "__main__":
    unittest.main()
