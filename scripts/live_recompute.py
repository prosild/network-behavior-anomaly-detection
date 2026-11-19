"""실습망 캡처 하루(lab-YYYYMMDD)를 그날 받은 파일 전체로 다시 계산한다(DD-012). 감시 프로그램이 Zeek 다음에 부른다.

예: python scripts/live_recompute.py --capture lab-20261201
출력: <runs_out>/<캡처 ID>/<리비전>/ (리비전 = 그날 지금까지 받은 파일 묶음, zeek_ad/live_capture.py)
- zeek/                 파일별 Zeek 로그를 합친 폴더(run-manifest.json 포함)
- captures.json, capture-bounds.json   기존 스크립트에 넘길 캡처 설정·경계
- silver/conn_v1/       Silver(scripts/build_silver_conn.py)
- gold/conn_features_v1/, events/tgn_v1/, gold/conn_features_v2/   Gold v1 → 이벤트 표 → Gold v2(합성 캡처와 같은 순서)
- graphs/tgn_v1/        TGN 그래프: 월요일 원래 이벤트 + 그날 이벤트(인코딩은 월요일 train으로 적합, 원래 그래프와 같아야 한다)
- worker-inputs.json    채점 worker·근거 요약에 넘길 입력 묶음 정의(configs/worker/inputs.v1.json과 같은 형식)
- pipeline.json         단계별 소요 시간과 결과
이어서 채점 worker(Registry champion 묶음) → 근거 요약을 DB에 쓰고, 이 리비전의 파일들을 처리 기록에서 pipeline_done으로 바꾼다.
같은 리비전이 이미 끝났으면 아무것도 하지 않는다.
성공하면 그날 오래된 리비전 폴더를 정리한다(설정 keep_revisions, zeek_ad/live_capture.prune_revisions).
정리가 실패해도 다시 계산 결과는 그대로 성공이다(경고만 출력).
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect  # noqa: E402
from zeek_ad.live_capture import capture_config, day_files, merge_zeek, prune_revisions, revision_id  # noqa: E402
from zeek_ad.provenance import project_path  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "pipeline" / "live.v1.json"
CIC_ASSETS = PROJECT_ROOT / "configs" / "assets.cic-ids-2017.v1.json"
MONDAY_EVENTS = PROJECT_ROOT / "outputs" / "events" / "tgn_v1"          # 월요일 원래 이벤트(그래프 앞부분)
MONDAY_ENCODING = PROJECT_ROOT / "outputs" / "graphs" / "tgn_v1" / "encoding.json"


def run_script(name, *args):
    """기존 배치 스크립트를 그대로 실행한다. 실패하면 마지막 출력 몇 줄과 함께 멈춘다."""
    result = subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / name), *map(str, args)],
                            capture_output=True, text=True, cwd=PROJECT_ROOT)
    if result.returncode != 0:
        tail = "\n".join((result.stdout + result.stderr).strip().splitlines()[-8:])
        raise RuntimeError(f"{name} 실패(종료 코드 {result.returncode})\n{tail}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, help="예: lab-20261201")
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument("--skip-failed", action="store_true",
                        help="이 리비전이 전에 실패했으면 다시 하지 않는다(감시 프로그램용. 같은 오류를 주기마다 반복하지 않게)")
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))

    with connect("zeekad_worker") as conn:
        files = day_files(conn, args.capture)
    if not files:
        sys.exit(f"{args.capture}: Zeek까지 끝난 파일이 없다")
    rev = PROJECT_ROOT / config["runs_out"] / args.capture / revision_id(files)
    record_path = rev / "pipeline.json"
    previous = json.loads(record_path.read_text(encoding="utf-8")).get("status") if record_path.exists() else None
    if previous == "done":
        print(f"이미 끝난 리비전: {project_path(rev)}")
        return
    if previous == "failed" and args.skip_failed:
        print(f"전에 실패한 리비전이라 건너뛴다: {project_path(rev)} (원인은 pipeline.json, 다시 하려면 이 스크립트를 직접 실행)")
        sys.exit(2)
    rev.mkdir(parents=True, exist_ok=True)
    record = {"capture_id": args.capture, "revision": rev.name, "files": [f["name"] for f in files],
              "started_at_utc": datetime.now(timezone.utc).isoformat(), "steps": [], "status": "running"}

    def step(name, fn):
        t = time.time()
        detail = fn()
        record["steps"].append({"step": name, "seconds": round(time.time() - t, 2), **(detail or {})})
        record_path.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"{name}: {record['steps'][-1]}", flush=True)

    zeek_dir, silver = rev / "zeek", rev / "silver" / "conn_v1"
    gold1, events, gold2, graph = (rev / "gold" / "conn_features_v1", rev / "events" / "tgn_v1",
                                   rev / "gold" / "conn_features_v2", rev / "graphs" / "tgn_v1")
    lab_assets = PROJECT_ROOT / config["assets"]
    caps, bounds = rev / "captures.json", rev / "capture-bounds.json"
    worker_inputs = rev / "worker-inputs.json"

    def merge():
        if not zeek_dir.exists():
            merge_zeek(files, zeek_dir)
        m = json.loads((zeek_dir / "run-manifest.json").read_text(encoding="utf-8"))
        return {"conn_rows": next(o["rows"] for o in m["outputs"] if o["name"] == "conn.log"),
                "logs": len(m["outputs"])}

    def configs():
        capture_config(args.capture, files, zeek_dir, rev)

    def build_silver():
        if not (silver / "_manifests" / f"{args.capture}.json").exists():
            run_script("build_silver_conn.py", "--run-dir", zeek_dir, "--capture-id", args.capture, "--out", silver)
        m = json.loads((silver / "_manifests" / f"{args.capture}.json").read_text(encoding="utf-8"))
        return {**m["counts"], "checks_passed": all(m["checks"].values())}

    def build_gold_v1():
        if not gold1.exists():
            run_script("build_gold.py", "--silver", silver, "--out", gold1, "--captures", caps, "--bounds", bounds,
                       "--assets", lab_assets)
        m = json.loads((gold1 / "manifest.json").read_text(encoding="utf-8"))
        by_split = {}
        for c in m["counts"]:                                   # 캡처·역할·창 라벨별 창 수
            by_split[c["split"]] = by_split.get(c["split"], 0) + c["count"]
        return {"windows_by_split": by_split, "checks_passed": all(m["checks"].values())}

    def build_events():
        # build_tgn_events는 설정의 zeek_run_dir 옆 --zeek-run 폴더를 읽는다. 합친 폴더 이름(zeek)을 그대로 준다.
        if not events.exists():
            run_script("build_tgn_events.py", "--silver", silver, "--zeek-run", zeek_dir.name, "--out", events,
                       "--captures", caps, "--bounds", bounds)
        m = json.loads((events / "manifest.json").read_text(encoding="utf-8"))
        u = m["uid_checks"][0]
        return {"events": m["counts"][0]["events"], "silver_uid_missing": u["silver_uid_missing_in_run02"]}

    def build_gold_v2():
        if not gold2.exists():
            run_script("build_gold_v2.py", "--gold-v1", gold1, "--events", events, "--out", gold2,
                       "--assets", lab_assets)
        m = json.loads((gold2 / "manifest.json").read_text(encoding="utf-8"))
        return {"windows": m["windows"], "checks_passed": all(m["checks"].values())}

    def build_graph():
        if not graph.exists():
            run_script("build_tgn_dataset.py", "--out", graph, "--events", MONDAY_EVENTS, events,
                       "--captures", "cic17-mon", args.capture, "--assets", CIC_ASSETS, lab_assets)
        m = json.loads((graph / "manifest.json").read_text(encoding="utf-8"))
        # 인코딩(어휘·표준화 값)은 월요일 train으로만 적합하므로 원래 그래프와 같아야 모델 입력 뜻이 같다
        mine = json.loads((graph / "encoding.json").read_text(encoding="utf-8"))
        base = json.loads(MONDAY_ENCODING.read_text(encoding="utf-8"))
        same = {k: mine[k] == base[k] for k in base if k != "t0_epoch_seconds"}
        if not all(same.values()):
            raise RuntimeError(f"그래프 인코딩이 원래 월요일 것과 다르다: {[k for k, v in same.items() if not v]}")
        s = m["summary"]
        return {"events": s["events"], "nodes": s["nodes"], "scored_nodes": s["scored_nodes"],
                "encoding_same_as_monday": True}

    def score():
        rel = lambda p: project_path(p)  # noqa: E731
        worker_inputs.write_text(json.dumps({
            "config_id": f"worker-inputs.{args.capture}.{rev.name}",
            "note": "live_recompute.py가 만든 실습망 리비전의 입력 묶음이다. 손으로 고치지 않는다.",
            "sets": {"live": {"captures": [args.capture], "gold_dir": rel(gold2), "graph_dir": rel(graph),
                              "bounds": rel(bounds), "events_dir": rel(events),
                              "zeek_run_dirs": {args.capture: rel(zeek_dir)}}}}, ensure_ascii=False, indent=1) + "\n",
            encoding="utf-8")
        out = run_script("run_worker.py", "--inputs", worker_inputs, "--set", "live")
        with connect("zeekad_worker") as conn:
            job = conn.execute("""SELECT j.job_id, j.status, (SELECT count(*) FROM zeekad.incident i WHERE i.job_id = j.job_id)
                                  FROM zeekad.scoring_job j WHERE j.capture_id = %s ORDER BY j.job_id DESC LIMIT 1""",
                               (args.capture,)).fetchone()
        record["job_id"] = job[0]
        return {"job_id": job[0], "job_status": job[1], "incidents": job[2], "worker_output": out.strip().splitlines()[-1]}

    def evidence():
        run_script("build_evidence.py", "--inputs", worker_inputs, "--set", "live", "--assets", lab_assets)
        with connect("zeekad_worker") as conn:
            n = conn.execute("SELECT count(*) FROM zeekad.incident_evidence WHERE job_id = %s",
                             (record["job_id"],)).fetchone()[0]
        return {"evidence_rows": n}

    def mark_done():
        with connect("zeekad_worker") as conn:
            n = conn.execute("""UPDATE zeekad.ingest_file SET status = 'pipeline_done', updated_at = now()
                                WHERE file_sha256 = ANY(%s) AND status = 'zeek_done'""",
                             ([f["sha256"] for f in files],)).rowcount
            conn.commit()
        return {"files_marked": n}

    try:
        step("merge_zeek", merge)
        step("capture_config", configs)
        step("silver", build_silver)
        step("gold_v1", build_gold_v1)
        step("events", build_events)
        step("gold_v2", build_gold_v2)
        step("graph", build_graph)
        step("score", score)
        step("evidence", evidence)
        step("mark_done", mark_done)
        record["status"] = "done"
    except Exception as e:
        record["status"] = "failed"
        record["error"] = f"{type(e).__name__}: {str(e)[:500]}"
        print(record["error"], file=sys.stderr)
    record["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    record_path.write_text(json.dumps(record, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if record["status"] != "done":
        sys.exit(1)
    try:
        pruned = prune_revisions(rev.parent, config.get("keep_revisions", 2))
    except OSError as e:
        print(f"경고: 오래된 리비전 정리 실패(다시 계산 결과는 그대로): {e}", file=sys.stderr)
    else:
        if pruned:
            print(f"오래된 리비전 {len(pruned)}개 정리({sum(p['bytes'] for p in pruned) / 1e6:.0f}MB): "
                  f"{', '.join(p['revision'] for p in pruned)}")


if __name__ == "__main__":
    main()
