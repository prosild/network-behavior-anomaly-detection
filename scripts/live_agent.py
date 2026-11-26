"""실습망 캡처의 최신 채점 작업 사건을 LangGraph 흐름으로 처리한다(DD-012, 단계 5b 흐름 재사용).

예: python scripts/live_agent.py --capture lab-20261201
- 그날 가장 최근에 성공한 채점 작업(= 최신 리비전)의 사건만 본다. 이전 리비전 작업은 대신하지 않는다.
- 같은 사건 ID(캡처|자산|역할|시작)를 이전 작업에서 이미 처리했으면 건너뛴다. 단, 그 뒤 사건을 이루는 창이 달라졌으면
  (뒤 파일에서 창이 이어 붙어 사건이 늘어남) 보고서·판단을 다시 만든다(DD-016 결정 3, agent_store.incidents_to_report).
  다시 처리해도 이미 알린 사건은 Slack에 다시 보내지 않는다(DD-016 결정 4). 같은 자산의 알림은 Slack 스레드로 묶는다(DD-010 결정 5).
- 두 차례로 나눈다(사건이 여러 건이어도 첫 알림이 밀리지 않게).
  1차: 모든 사건을 근거 수집 → 검색 → 템플릿 알림(정책 규칙 보냄일 때)까지 돌리고 early_alert 뒤에서 멈춘다(interrupt_after).
       멈춘 상태는 checkpoint(PostgreSQL langgraph 스키마)에 남는다.
  2차: 같은 thread_id로 하나씩 이어서 LLM 보고서 → 판단 → LLM 보고서 알림. Slack은 dry-run.
- 사건마다 실패를 따로 잡는다(run_two_phases). 한 사건이 실패해도 나머지는 끝까지 간다. 1차에서 실패한 사건은 2차를 건너뛴다.
  실패가 있으면 종료 코드 1이다. 감시 프로그램(live_watcher.py)이 다음 주기에 다시 부른다(agent_retries번까지).
  다시 부르면 끝나지 못한 사건만 고른다: 보고서가 없거나, 보고서는 있지만 전송 판단이 없는 사건('retry').
- API 한도 초과(429)를 한 번 만나면 이 실행의 남은 LLM 호출은 하지 않는다(zeek_ad.quota). 그 사건들은 템플릿 보고서만
  남고 실패로 끝나므로 위 규칙대로 다음 실행이 다시 고른다. 한도가 풀린 뒤 손으로 부르면 바로 따라잡는다.
- --redo-failed-calls: 판단까지 끝났지만 API 호출이 실패했던 사건(템플릿 보고서, 판단 모델 실패)도 다시 만든다('redo').
  시간 초과 같은 실패는 템플릿으로 끝난 것으로 치므로 보통 실행은 다시 고르지 않는다. 손으로 다시 만들 때만 쓴다.
- 입력 설정은 그 리비전의 worker-inputs.json(Gold 위치)과 configs/assets.lab.v1.json(내부 대역)이다.
  작업의 리비전은 입력 지문(scoring_job.input_manifest_sha256)이 같은 리비전이다(revision_for_job). 작업 = 입력 + 묶음이라
  묶음을 바꿔 같은 리비전을 다시 채점한 작업(단계 7 교체·롤백)도 찾는다.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from run_agent_graph import checkpointer, resources, traced_run  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "pipeline" / "live.v1.json"


def revision_for_job(capture_dir, capture_id, input_sha):
    """입력 지문이 같은 리비전 폴더. 없으면 None. 지문은 채점 worker가 작업을 만들 때 쓴 것과 같은 함수로 계산한다.

    큐 자격 규칙 항목(queue_eligibility)이 있는 리비전은 규칙 입력까지 넣은 지문, 없는 옛 리비전은 예전 지문이다.
    """
    from zeek_ad.worker import set_input_fingerprint

    for inputs in sorted(Path(capture_dir).glob("rev-*/worker-inputs.json")):
        cfg = json.loads(inputs.read_text(encoding="utf-8"))["sets"]["live"]
        try:
            sha, _ = set_input_fingerprint(cfg, capture_id, PROJECT_ROOT)
        except FileNotFoundError:
            continue                      # 계산이 중간에 끊긴 리비전
        if sha == input_sha:
            return inputs.parent
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True)
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--no-trace", action="store_true")
    parser.add_argument("--redo-failed-calls", action="store_true",
                        help="API 호출 실패로 템플릿·판단 실패가 된 사건도 다시 만든다")
    parser.add_argument("--only", action="append", default=[], metavar="INCIDENT_ID",
                        help="고른 사건 중 이 사건만 처리한다(여러 번 쓸 수 있다)")
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))

    from zeek_ad.agent_graph import build_graph
    from zeek_ad.agent_store import failed_call_incidents, incidents_to_report, with_redo
    from zeek_ad.db import connect

    with connect("zeekad_worker", autocommit=True) as conn:
        job = conn.execute("""SELECT job_id, input_manifest_sha256 FROM zeekad.scoring_job
                              WHERE capture_id = %s AND status = 'succeeded'
                              ORDER BY job_id DESC LIMIT 1""", (args.capture,)).fetchone()
        if job is None:
            sys.exit(f"{args.capture}: 성공한 채점 작업이 없다")
        job_id, input_sha = job
        picked = incidents_to_report(conn, job_id, args.capture)
        if args.redo_failed_calls:
            picked = with_redo(picked, failed_call_incidents(conn, job_id, args.capture))
    if args.only:
        picked = [(iid, reason) for iid, reason in picked if iid in args.only]
    todo = [iid for iid, _ in picked]
    counts = {r: sum(reason == r for _, reason in picked) for r in ("new", "changed", "retry", "redo")}
    # 이 작업의 입력 묶음 정의(리비전 폴더)를 찾는다: 입력 지문이 같은 리비전
    rev = revision_for_job(PROJECT_ROOT / config["runs_out"] / args.capture, args.capture, input_sha.strip())
    if rev is None:
        sys.exit(f"작업 {job_id}의 리비전 폴더를 찾지 못했다")
    print(f"{args.capture}: 작업 {job_id}, 리비전 {rev.name}, 처리할 사건 {len(todo)}건"
          f"(새 사건 {counts['new']}, 늘어난 사건 {counts['changed']}, 다시 시도 {counts['retry']}"
          + (f", 호출 실패 다시 {counts['redo']}" if counts["redo"] else "") + ")", flush=True)
    if not todo:
        return 0

    res = resources({"assets": [PROJECT_ROOT / config["assets"]], "worker_inputs": rev / "worker-inputs.json"})
    res["source"] = f"live-agent.v1:{rev.name}"
    graph = build_graph({**res, "tracing": not args.no_trace}, checkpointer())
    started = time.time()

    def run_phase(command, iid):
        """command: start(처음부터 early_alert 뒤까지) 또는 continue(멈춘 곳부터 끝까지). 반환: (실행한 노드, 다음 노드)."""
        cfg = {"configurable": {"thread_id": f"{job_id}|{iid}"}}
        payload, kwargs = (({"job_id": job_id, "incident_id": iid}, {"interrupt_after": ["early_alert"]})
                           if command == "start" else (None, {}))
        nodes = []

        def run():
            for chunk in graph.stream(payload, cfg, stream_mode="updates", **kwargs):
                nodes.extend(n for n in chunk if n != "__interrupt__")

        if args.no_trace:
            run()
        else:
            traced_run(res["conn"], argparse.Namespace(job=job_id, incident=iid, command=command), run)
        return nodes, list(graph.get_state(cfg).next)

    failed = run_two_phases(todo, run_phase, started)
    if failed:
        print(f"{args.capture}: 실패한 사건 {len(failed)}건 / {len(todo)}건. 다음 실행에서 다시 고른다", flush=True)
        return 1
    return 0


def label(iid):
    return " ".join(iid.split("|")[1:3])      # 자산 역할


def run_two_phases(todo, run_phase, started, log=print):
    """1차(템플릿 알림까지)를 모든 사건에, 2차(LLM 보고서·판단·전송)를 1차가 성공한 사건에 돌린다.

    사건 하나의 예외는 그 사건만 실패로 남기고 다음 사건으로 넘어간다. 반환: {incident_id: 실패 설명}.
    LangGraph가 노드 안의 예외를 그대로 던지므로 여기서 잡는다. 실패한 thread의 checkpoint는 남지만,
    다음 실행이 같은 thread_id에 새 입력으로 처음부터 다시 시작한다(이미 기록한 Slack은 같은 키라 다시 남지 않는다).
    """
    failed = {}

    def attempt(phase, command, iid):
        try:
            nodes, nxt = run_phase(command, iid)
        except Exception as e:  # noqa: BLE001 (사건 하나의 어떤 실패도 다른 사건을 막지 않게 한다)
            failed[iid] = f"{phase} {type(e).__name__}: {str(e)[:200]}"
            log(f"  {phase} {label(iid)}: 실패 {failed[iid]}", flush=True)
            return
        log(f"  {phase} {label(iid)}: 시작 후 {time.time() - started:.1f}초, 노드 {nodes}, "
            f"다음 {nxt or '끝'}", flush=True)

    # 1차: 템플릿 알림까지
    for iid in todo:
        attempt("1차", "start", iid)
    # 2차: LLM 보고서·판단·전송 기록(분석가 검토가 필요하면 analyst_review에서 다시 멈춘다)
    for iid in todo:
        if iid not in failed:
            attempt("2차", "continue", iid)
    return failed


if __name__ == "__main__":
    raise SystemExit(main())
