"""사건 하나를 LangGraph 흐름(zeek_ad/agent_graph.py)으로 처리한다. 상태는 PostgreSQL(langgraph 스키마)에 저장된다.

- 그림:   python scripts/run_agent_graph.py draw
- 시작:   python scripts/run_agent_graph.py start --job 4 --incident 'cic17-fri|192.168.10.5|originator|...'
          (분석가 검토가 필요하면 멈추고, 멈춘 지점의 질문을 출력한다)
- 상태:   python scripts/run_agent_graph.py status --job 4 --incident '...'
- 재개:   python scripts/run_agent_graph.py resume --job 4 --incident '...' --action confirm --analyst a1 --note '...'
thread_id는 "job_id|incident_id"다. 같은 thread_id로 재개하면 멈춘 노드부터 이어서 실행한다.
"""

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

CONFIGS = PROJECT_ROOT / "configs" / "agent"


def checkpointer():
    """langgraph 스키마에 상태를 저장하는 PostgresSaver. 처음이면 표를 만든다(setup)."""
    import psycopg
    from psycopg.rows import dict_row
    from langgraph.checkpoint.postgres import PostgresSaver
    from zeek_ad.db import PASSWORD_KEYS, db_address, load_env

    env = load_env()
    host, port = db_address(env)
    conn = psycopg.connect(host=host, port=port, dbname="zeekad",
                           user="zeekad_worker", password=env[PASSWORD_KEYS["zeekad_worker"]], autocommit=True,
                           prepare_threshold=0, row_factory=dict_row, options="-c search_path=langgraph")
    saver = PostgresSaver(conn)
    saver.setup()
    return saver


def resources(ctx_options=None):
    """그래프가 쓰는 연결·설정. ctx_options: InputContext에 넘길 assets·worker_inputs(실습망 리비전, DD-012)."""
    from google import genai
    from zeek_ad.agent_inputs import InputContext
    from zeek_ad.db import connect, load_env

    key = load_env()["GEMINI_API_KEY"]
    # v2: 요청 모델을 실제 응답 모델(gemini-3.8-flash)과 맞춘 운영 설정(Q64). 평가 동결 v1은 run_agent_reports.py가 그대로 쓴다
    report_cfg = json.loads((CONFIGS / "report.v2.json").read_text(encoding="utf-8"))
    send_cfg = json.loads((CONFIGS / "send-decision.v1.json").read_text(encoding="utf-8"))
    dm = send_cfg["decision_model"]
    return {
        "conn": connect("zeekad_worker", autocommit=True),
        "ctx": InputContext(api_key=key, **(ctx_options or {})),
        "client_llm": genai.Client(api_key=key, http_options={"api_version": report_cfg["api_version"],
                                                              "timeout": report_cfg["timeout_seconds"] * 1000}),
        # 판단 모델 쪽 SDK는 기본으로 안에서 4번 더 부른다(429·5xx). call_decision이 이미 다시 부르므로 SDK 재시도는 끈다
        "client_decision": genai.Client(api_key=key, http_options={"api_version": dm["api_version"],
                                                                   "timeout": dm["timeout_seconds"] * 1000,
                                                                   "retry_options": {"attempts": 1}}),
        "report_config": report_cfg,
        "system_prompt": (PROJECT_ROOT / report_cfg["system_prompt"]).read_text(encoding="utf-8"),
        "send_config": send_cfg,
        # v2: 같은 자산 알림 묶음(DD-010 결정 5). 배치 도구 scripts/run_slack.py는 v1 그대로 쓴다
        "slack_config": json.loads((CONFIGS / "slack.v2.json").read_text(encoding="utf-8")),
        "source": "agent-graph.v1",
    }


def traced_run(conn, args, run):
    """그래프 실행 한 번 = MLflow trace 하나. 사건은 IP가 든 incident_id 대신 캡처·작업·큐 순위로 표시한다."""
    import mlflow
    from zeek_ad.agent_graph import mark_failed
    from zeek_ad.db import mlflow_tracking_uri

    mlflow.set_tracking_uri(mlflow_tracking_uri())
    mlflow.set_experiment("zeekad-agent-traces")
    capture, rank = conn.execute("""SELECT j.capture_id, i.queue_rank FROM incident i JOIN scoring_job j USING (job_id)
                                    WHERE i.job_id = %s AND i.incident_id = %s""", (args.job, args.incident)).fetchone()
    failed = None
    with mlflow.start_span(name=f"incident_flow.{args.command}", span_type="AGENT") as root:
        root.set_attributes({"zeekad.capture_id": capture, "zeekad.job_id": args.job, "zeekad.queue_rank": rank,
                             "zeekad.command": args.command})
        mlflow.update_current_trace(tags={"zeekad.capture_id": capture, "zeekad.job_id": str(args.job),
                                          "zeekad.queue_rank": str(rank), "zeekad.command": args.command})
        try:
            run()
        except Exception as e:  # noqa: BLE001 (예외 문장에 실제 IP가 섞일 수 있어 trace에는 종류만. 예외는 다시 던진다)
            mark_failed(root, e)
            failed = e
    mlflow.flush_trace_async_logging()
    print(f"MLflow trace: {mlflow.get_last_active_trace_id()} (실험 zeekad-agent-traces)")
    if failed is not None:
        raise failed


def show(chunks):
    """stream_mode="updates": 노드 하나가 끝날 때마다 {노드: 바뀐 상태}가 온다."""
    for chunk in chunks:
        for node, update in chunk.items():
            if node == "__interrupt__":
                for it in update:
                    print("⏸ interrupt — 분석가 결정을 기다린다:")
                    print(json.dumps(it.value, ensure_ascii=False, indent=1))
                continue
            for t in (update or {}).get("trace", []):
                print(f"● {node}: " + json.dumps({k: v for k, v in t.items() if k != "node"}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["draw", "start", "status", "resume"])
    parser.add_argument("--job", type=int)
    parser.add_argument("--incident")
    parser.add_argument("--action", choices=["confirm", "dismiss"])
    parser.add_argument("--analyst")
    parser.add_argument("--note")
    parser.add_argument("--no-trace", action="store_true", help="MLflow trace를 남기지 않는다")
    args = parser.parse_args()
    if args.command == "resume" and not (args.action and args.analyst):
        parser.error("resume에는 --action과 --analyst가 필요하다(상태 이력에 누가 바꿨는지 남긴다)")

    from langgraph.types import Command
    from zeek_ad.agent_graph import build_graph

    if args.command == "draw":
        print(build_graph({"conn": None, "ctx": None}).get_graph().draw_mermaid())
        return
    res = resources()
    graph = build_graph({**res, "tracing": not args.no_trace}, checkpointer())
    cfg = {"configurable": {"thread_id": f"{args.job}|{args.incident}"}}
    run = None
    if args.command == "start":
        run = lambda: show(graph.stream({"job_id": args.job, "incident_id": args.incident}, cfg,  # noqa: E731
                                        stream_mode="updates"))
    elif args.command == "resume":
        run = lambda: show(graph.stream(Command(resume={"action": args.action, "analyst": args.analyst,  # noqa: E731
                                                        "note": args.note}), cfg, stream_mode="updates"))
    if run and args.no_trace:
        run()
    elif run:
        traced_run(res["conn"], args, run)
    state = graph.get_state(cfg)
    print(f"다음 노드: {list(state.next) or '끝'} | 저장된 checkpoint: {state.config['configurable'].get('checkpoint_id')}")


if __name__ == "__main__":
    main()
