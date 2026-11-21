"""LLM 보고서 설정 v1(평가 동결)·v2(운영) 시험(Q64). 표준 라이브러리만 쓴다."""

import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "configs" / "agent"


def load(name):
    return json.loads((CONFIGS / name).read_text(encoding="utf-8"))


class ReportConfigTest(unittest.TestCase):
    def test_v1_still_matches_freeze(self):
        # 평가 동결 파일은 손대지 않는다. 운영 변경은 v2로만 한다
        freeze = load("freeze.v1.json")
        entry = next(f for f in freeze["files"] if f["path"] == "configs/agent/report.v1.json")
        digest = hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest()
        self.assertEqual(digest, entry["sha256"])
        self.assertEqual(load("report.v1.json")["model"], freeze["llm_model_requested"])

    def test_v2_changes_only_model(self):
        # v2는 요청 모델만 다르다. 프롬프트·온도·시간 제한이 바뀌면 평가 결과와 비교할 수 없다
        v1, v2 = load("report.v1.json"), load("report.v2.json")
        self.assertEqual(v2["model"], "gemini-3.8-flash")
        changed = {k for k in v1.keys() | v2.keys() if v1.get(k) != v2.get(k)}
        self.assertEqual(changed, {"config_id", "note", "model"})

    def test_graph_reads_v2(self):
        # 운영 LangGraph는 v2를 읽고, 평가 재현 도구는 v1을 읽는다
        graph = (ROOT / "scripts" / "run_agent_graph.py").read_text(encoding="utf-8")
        reports = (ROOT / "scripts" / "run_agent_reports.py").read_text(encoding="utf-8")
        self.assertIn('"report.v2.json"', graph)
        self.assertNotIn('"report.v1.json"', graph)
        self.assertIn('"report.v1.json"', reports)


if __name__ == "__main__":
    unittest.main()
