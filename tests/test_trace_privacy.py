"""MLflow trace에 예외 문장(실제 IP가 섞일 수 있음)이 남지 않는지 실제 MLflow로 확인한다(임시 SQLite 저장소).

zeek-ad 환경에서 실행한다: python -m unittest tests.test_trace_privacy -v (MLflow 저장소를 만드느라 몇 초 걸린다)
확인하는 것:
- 노드 span(agent_graph.traced)과 사건 span(run_agent_graph.traced_run)은 예외가 나면 오류 상태와 예외 종류만 남긴다.
- 예외 문장 속 IP·사건 ID는 trace 어디에도 없다. 예외는 그대로 다시 던진다(사건별 실패 처리가 그대로 동작).
"""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
os.environ["MLFLOW_ENABLE_ASYNC_TRACE_LOGGING"] = "false"
import mlflow  # noqa: E402

from zeek_ad import agent_graph  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_agent_graph  # noqa: E402

SECRET = "Key (job_id, incident_id)=(31, lab-20261118|10.10.0.10|responder|1794994800) already exists."


class TracePrivacyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        mlflow.set_tracking_uri(f"sqlite:///{cls.tmp.name}/mlflow.db")
        mlflow.set_experiment("trace-privacy-test")

    @classmethod
    def tearDownClass(cls):
        mlflow.set_tracking_uri(None)
        cls.tmp.cleanup()

    def last_trace_text(self):
        trace = mlflow.get_trace(mlflow.get_last_active_trace_id())
        text = " ".join(str(s.attributes) + str([(e.name, e.attributes) for e in s.events]) + str(s.status)
                        for s in trace.data.spans)
        return trace, text

    def test_node_and_incident_spans_hide_message(self):
        def boom(state):
            raise RuntimeError(SECRET)

        node = agent_graph.traced("write_report", boom)
        conn = mock.Mock()
        conn.execute.return_value.fetchone.return_value = ("lab-20261118", 1)
        args = mock.Mock(job=31, incident="lab-20261118|10.10.0.10|responder|1794994800", command="continue")
        with mock.patch("zeek_ad.db.mlflow_tracking_uri", return_value=mlflow.get_tracking_uri()):
            with self.assertRaises(RuntimeError) as ctx:
                run_agent_graph.traced_run(conn, args, lambda: node({}))
        self.assertIn("10.10.0.10", str(ctx.exception))          # 예외 자체는 그대로(로그·실패 처리용)
        trace, text = self.last_trace_text()
        self.assertNotIn("10.10.0.10", text)
        self.assertNotIn("already exists", text)
        self.assertEqual(str(trace.info.state).split(".")[-1], "ERROR")
        node_span = next(s for s in trace.data.spans if s.name == "write_report")
        self.assertEqual(node_span.attributes.get("zeekad.error_type"), "RuntimeError")
        self.assertEqual(str(node_span.status.status_code).split(".")[-1], "ERROR")


if __name__ == "__main__":
    unittest.main()
