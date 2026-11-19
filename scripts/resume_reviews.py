"""대시보드에서 결정한 분석가 검토로 멈춘 흐름을 재개한다(DD-019). 감시 프로그램이 결정된 검토가 있을 때 부른다.

예: python scripts/resume_reviews.py            (결정됐지만 재개 안 된 검토 전부)
결정 넣기(대시보드 대신 시험할 때, worker 계정):
    SELECT dashboard.decide_review(<작업>, '<사건 ID>', 'dismiss', '<분석가>', '<메모>');
종료 코드: 0(모두 재개 또는 할 것 없음), 1(하나라도 실패. 이유는 analyst_review.resume_error)
"""

import argparse
from pathlib import Path
import sys
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from zeek_ad.db import connect  # noqa: E402
from zeek_ad.review_resume import decided_reviews, resume_one  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-trace", action="store_true", help="MLflow trace를 남기지 않는다")
    args = parser.parse_args()

    with connect("zeekad_worker", autocommit=True) as conn:
        todo = decided_reviews(conn)
    print(f"재개할 검토 {len(todo)}건", flush=True)
    if not todo:
        return 0

    from langgraph.types import Command
    from run_agent_graph import checkpointer, resources, traced_run
    from zeek_ad.agent_graph import build_graph

    # 재개 뒤 노드(analyst_review·apply_status)는 입력 묶음(Gold)을 읽지 않는다. 그래서 기본 입력 설정으로 만든다
    # (실습망 리비전 폴더는 정리됐을 수 있다).
    res = resources()
    graph = build_graph({**res, "tracing": not args.no_trace}, checkpointer())
    conn, failed = res["conn"], 0
    for review in todo:
        label = conn.execute("""SELECT j.capture_id, i.queue_rank FROM incident i JOIN scoring_job j USING (job_id)
                                WHERE i.job_id = %s AND i.incident_id = %s""",
                             (review["job_id"], review["incident_id"])).fetchone()
        outcome = {}

        def run(review=review):
            outcome["value"] = resume_one(graph, conn, review, Command)

        if args.no_trace:
            run()
        else:
            traced_run(conn, SimpleNamespace(job=review["job_id"], incident=review["incident_id"], command="resume"), run)
        failed += outcome["value"] != "resumed"
        # 사건 ID에는 실제 IP가 있어 출력에는 캡처·작업·큐 순위만 쓴다
        print(f"  {label[0]} 작업 {review['job_id']} {label[1]}위: {review['action']} → {outcome['value']}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
