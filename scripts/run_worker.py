"""추론 worker 실행(단계 4): Registry 묶음으로 캡처를 채점하고 결합 큐를 PostgreSQL에 저장한다.

예: python scripts/run_worker.py --set cic synthetic
- 시작할 때 alias(기본 champion)를 버전으로 풀어 고정한다. 이 실행의 모든 작업이 같은 버전을 쓴다.
- 같은 캡처·입력·묶음은 한 번만 저장된다. 다시 돌리면 succeeded 작업은 건너뛴다.
- set에 queue_eligibility 항목(규칙 설정·자산 설정·Silver 경로)이 있으면 큐 자격 규칙을 적용한다
  (zeek_ad/queue_eligibility.py). 브로드캐스트·멀티캐스트행 연결만 있고 그 수가 설정 상한 이하인 originator 창에
  라벨(non_host_only)을 붙여 결합 큐에서 빼고, 창 점수는 라벨과 함께 저장한다. 상한을 넘는 창은 큐에 남긴다.
  규칙 입력은 작업 입력 지문에 들어간다. 항목이 없는 set(CIC·합성)은 계산과 지문이 예전과 같다.
입력 묶음 정의: configs/worker/inputs.v1.json(실습망은 live_recompute.py가 쓴 리비전의 worker-inputs.json).
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
from zeek_ad.queue_eligibility import apply_to_set  # noqa: E402
from zeek_ad.worker import (  # noqa: E402
    lock_job, mark_failed, open_job, resolve_bundle, set_input_fingerprint, upsert_bundle, write_results,
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


def job_input_sha(cfg, capture_id, root=PROJECT_ROOT):
    """작업 키의 입력 지문. set에 queue_eligibility 항목이 있으면 규칙 입력까지 넣는다(live_agent.revision_for_job과 같은 함수)."""
    return set_input_fingerprint(cfg, capture_id, root)[0]


def score_job(model, cfg, capture_id, bound, root=PROJECT_ROOT):
    """점수 → 큐 자격 규칙 → 결합 큐. DB는 쓰지 않는다(트랜잭션 밖, 오래 걸림).

    bound: 캡처 경계 한 행(packet_time_min, pcap_sha256). 반환 dict:
    - scores: DB에 쓸 표. 라벨(non_host_only)을 바꾼 전체 창 점수(점수는 남고 split으로 이유가 보인다)
    - fused, sources, queues: 라벨 창을 뺀 표로 만든 결합 큐
    - eligibility: 규칙 요약(항목이 없으면 None)
    """
    raw = model.score_capture(capture_id, Path(root) / cfg["gold_dir"], Path(root) / cfg["graph_dir"],
                              bound["packet_time_min"])
    scores, queue_scores, eligibility = apply_to_set(raw, cfg, capture_id, root)
    fused, sources, queues = model.build_queue(queue_scores, {capture_id: bound["pcap_sha256"]})
    return {"scores": scores, "fused": fused, "sources": sources, "queues": queues, "eligibility": eligibility}


def store_job(conn, job_id, job, fault_hook=None):
    """score_job 결과를 쓴다(호출한 쪽 트랜잭션 안). 창 점수는 큐용 표가 아니라 라벨을 바꾼 전체 표다."""
    write_results(conn, job_id, job["scores"], job["fused"], job["sources"], job["queues"], fault_hook)


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
            bounds_path = PROJECT_ROOT / cfg["bounds"]
            bounds = {c["capture_id"]: c for c in json.loads(bounds_path.read_text(encoding="utf-8"))["captures"]}
            for cap in cfg["captures"]:
                if args.captures and cap not in args.captures:
                    continue
                # 지문 계산은 try 밖이다. Silver manifest가 없으면 작업 행 없이 끝나는데, live_recompute의 Silver 단계가
                # manifest를 먼저 확인하므로 그대로 둔다.
                input_sha = job_input_sha(cfg, cap, PROJECT_ROOT)
                job_id, state = open_job(conn, cap, input_sha, bundle["bundle_id"])
                if state == "done":
                    print(f"{cap}: job {job_id} 이미 완료, 건너뜀", flush=True)
                    continue
                began = time.perf_counter()
                try:
                    job = score_job(model, cfg, cap, bounds[cap], PROJECT_ROOT)
                    with conn.transaction():
                        if not lock_job(conn, job_id):
                            print(f"{cap}: job {job_id} 다른 worker가 먼저 끝냄, 쓰지 않음", flush=True)
                            continue
                        store_job(conn, job_id, job, fault)
                        fault("before_commit")
                    fault("after_commit")
                except Exception as e:
                    with conn.transaction():
                        mark_failed(conn, cap, input_sha, bundle["bundle_id"], f"{type(e).__name__}: {e}")
                    raise
                # 뺀 창 수와, 브로드캐스트만 있지만 연결 수가 상한을 넘어 큐에 남긴 창 수
                eligibility = job["eligibility"]
                excluded = (f"{eligibility['label']}_windows={eligibility['excluded_windows']} "
                            f"over_limit_kept={eligibility['over_limit_windows']} " if eligibility else "")
                print(f"{cap}: job {job_id} ({state}) windows={len(job['scores']) // 3} incidents={len(job['fused'])} "
                      f"{excluded}{time.perf_counter() - began:.0f}s", flush=True)


if __name__ == "__main__":
    main()
