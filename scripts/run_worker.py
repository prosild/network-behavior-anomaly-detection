"""추론 worker 실행(단계 4): Registry 묶음으로 캡처를 채점하고 결합 큐를 PostgreSQL에 저장한다.

예: python scripts/run_worker.py --set cic synthetic
- 시작할 때 alias(기본 champion)를 버전으로 풀어 고정한다. 이 실행의 모든 작업이 같은 버전을 쓴다.
- 같은 캡처·입력·묶음은 한 번만 저장된다. 다시 돌리면 succeeded 작업은 건너뛴다.
입력 묶음 정의: configs/worker/inputs.v1.json.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import time

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
import mlflow  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect, mlflow_tracking_uri  # noqa: E402
from zeek_ad.worker import (  # noqa: E402
    input_fingerprint, lock_job, mark_failed, open_job, resolve_bundle, upsert_bundle, write_results,
)

INPUTS = PROJECT_ROOT / "configs" / "worker" / "inputs.v1.json"


def fault(point):
    """장애 복구 시험용(scripts/test_worker_recovery.py). ZEEKAD_FAULT가 이 지점이면 일부러 멈춘다.

    os._exit는 정리 코드(except, with 종료) 없이 프로세스를 바로 끝낸다. 전원이 나간 것과 비슷하다.
    raise_<지점>은 예외를 던져 정상 실패 경로(롤백 → failed 기록)를 시험한다.
    """
    target = os.environ.get("ZEEKAD_FAULT")
    if target == point:
        print(f"FAULT: {point}에서 프로세스를 끝낸다", flush=True)
        os._exit(17)
    if target == f"raise_{point}":
        raise RuntimeError(f"시험용 예외: {point}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", nargs="+", default=["cic"], dest="sets")
    parser.add_argument("--captures", nargs="*", help="이 캡처만 채점한다(기본: 묶음의 모든 캡처)")
    parser.add_argument("--alias", default="champion")
    parser.add_argument("--db", default="zeekad", help="장애 복구 시험은 zeekad_test를 쓴다")
    # 실습망 리비전(DD-012)은 scripts/live_recompute.py가 만든 <리비전>/worker-inputs.json을 준다.
    parser.add_argument("--inputs", type=Path, default=INPUTS, help="입력 묶음 정의 파일")
    args = parser.parse_args()

    mlflow.set_tracking_uri(mlflow_tracking_uri())
    bundle = resolve_bundle(args.alias)
    model = bundle["model"]
    print(f"bundle {bundle['bundle_id']} (alias {args.alias}), manifest {bundle['manifest_sha256'][:12]}", flush=True)
    inputs = json.loads(args.inputs.read_text(encoding="utf-8"))["sets"]

    with connect("zeekad_worker", dbname=args.db, autocommit=True) as conn:
        with conn.transaction():
            upsert_bundle(conn, bundle)
        for name in args.sets:
            cfg = inputs[name]
            gold_dir, graph_dir = PROJECT_ROOT / cfg["gold_dir"], PROJECT_ROOT / cfg["graph_dir"]
            bounds_path = PROJECT_ROOT / cfg["bounds"]
            bounds = {c["capture_id"]: c for c in json.loads(bounds_path.read_text(encoding="utf-8"))["captures"]}
            for cap in cfg["captures"]:
                if args.captures and cap not in args.captures:
                    continue
                input_sha, _ = input_fingerprint(gold_dir, graph_dir, bounds_path, cap)
                job_id, state = open_job(conn, cap, input_sha, bundle["bundle_id"])
                if state == "done":
                    print(f"{cap}: job {job_id} 이미 완료, 건너뜀", flush=True)
                    continue
                began = time.perf_counter()
                try:
                    scores = model.score_capture(cap, gold_dir, graph_dir, bounds[cap]["packet_time_min"])
                    fused, sources, queues = model.build_queue(scores, {cap: bounds[cap]["pcap_sha256"]})
                    with conn.transaction():
                        if not lock_job(conn, job_id):
                            print(f"{cap}: job {job_id} 다른 worker가 먼저 끝냄, 쓰지 않음", flush=True)
                            continue
                        write_results(conn, job_id, scores, fused, sources, queues, fault)
                        fault("before_commit")
                    fault("after_commit")
                except Exception as e:
                    with conn.transaction():
                        mark_failed(conn, cap, input_sha, bundle["bundle_id"], f"{type(e).__name__}: {e}")
                    raise
                print(f"{cap}: job {job_id} ({state}) windows={len(scores) // 3} incidents={len(fused)} "
                      f"{time.perf_counter() - began:.0f}s", flush=True)


if __name__ == "__main__":
    main()
