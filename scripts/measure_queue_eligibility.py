"""큐 자격 규칙(configs/worker/queue-eligibility.v1.json) 적용 전후의 조사 큐를 VM DB 내보내기로 견준다(측정 전용).

DB·MLflow·묶음 로딩 없이 저장된 창 점수로 큐를 다시 만든다. 큐 계산은 묶음과 같은 함수
(evaluation.build_incidents·rank_queue, fusion.fuse)를 그대로 부르고, 임계값·결합 설정은 model_bundle.csv의 manifest에서 읽는다.

입력(읽기만)
- <export-dir>의 scoring_job·window_score·incident·incident_window·slack_delivery·agent_report·model_bundle CSV,
  그리고 ingest_file CSV(동점 순서 해시 tie_key에 들어가는 "입력 캡처 해시"를 그날 파일 해시로 다시 만든다,
  live_capture.capture_config와 같은 식)
- outputs/live/zeek/<캡처>/<5분 파일 폴더>/conn.log(JSON lines, uid는 파일 사이에서 겹친다. 창 판정에는 uid를 쓰지 않는다)
- 규칙 설정, 자산 설정(내부 대역), 정답 설정(lab-attacks.v1)
순서
1. 캡처마다 마지막 성공 작업 J를 고른다. 규칙 없이 다시 만든 큐가 DB의 사건(사건 ID, 순위, 창)과 같은지 먼저 본다.
   다르면 다른 점을 출력하고 종료 코드 1. conn.log의 창이 J의 originator 창과 맞지 않아도 종료 코드 1(다른 입력이다).
2. 규칙(연결 수 상한 포함)을 적용한 큐를 만들어 전후를 견준다. 공격 에피소드마다 당사자 단위의 공격 창을 담은 사건의
   전후 순위를 낸다. 상한을 넘어 큐에 남긴 창 수도 남긴다.
3. 선택: --baseline-silver를 주면 상한의 출처(CIC 월요일 originator 창마다 호스트가 아닌 주소행 연결 수의 중앙·p99·최대)를
   다시 계산해 설정의 상한과 같은지 표시한다. Silver를 pandas로 읽으므로 이때만 zeek-ad 환경이 필요하다. 자료가 없으면 건너뛴다.
출력: <out-dir>/result.json(전체 결과, 입력 해시), <out-dir>/result.md(표).

예: python3 scripts/measure_queue_eligibility.py
    conda run -n zeek-ad python scripts/measure_queue_eligibility.py --baseline-silver outputs/silver/conn_v1/conn \
        --baseline-assets configs/assets.cic-ids-2017.v1.json
"""

import argparse
from collections import defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import statistics
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.assets import ORIGINATOR, is_scored_asset, load_networks  # noqa: E402
from zeek_ad.evaluation import build_incidents, percentile, rank_queue  # noqa: E402
from zeek_ad.fusion import fuse  # noqa: E402
from zeek_ad.lab_detection import is_true, last_job, parse_db_time  # noqa: E402
from zeek_ad.lab_truth import attack_windows, episode_capture, load_config as load_truth, read_capture_conn  # noqa: E402
from zeek_ad.live_capture import files_sha256  # noqa: E402
from zeek_ad.provenance import file_record, project_path, sha256  # noqa: E402
from zeek_ad.queue_eligibility import count_connections, label_rows, load_config, scan_connections  # noqa: E402
from zeek_ad import windows as time_windows  # noqa: E402

CAPTURES = ["lab-20261119", "lab-20261122", "lab-20261123", "lab-20261124", "lab-20261125"]
TABLES = ["scoring_job", "window_score", "incident", "incident_window", "slack_delivery", "agent_report",
          "model_bundle", "ingest_file"]
EXPORT = PROJECT_ROOT / "outputs" / "lab_eval" / "vm-export-20261126"
ZEEK_ROOT = PROJECT_ROOT / "outputs" / "live" / "zeek"
RULE = PROJECT_ROOT / "configs" / "worker" / "queue-eligibility.v1.json"
ASSETS = PROJECT_ROOT / "configs" / "assets.lab.v1.json"
TRUTH = PROJECT_ROOT / "configs" / "ground-truth" / "lab-attacks.v1.json"
OUT = PROJECT_ROOT / "outputs" / "lab_eval" / "queue_eligibility" / "v1"
EDGE = "capture_edge"
CODE_FILES = [PROJECT_ROOT / "zeek_ad" / f for f in ["queue_eligibility.py", "evaluation.py", "fusion.py", "windows.py"]] \
    + [Path(__file__).resolve()]


def read_csv(path):
    csv.field_size_limit(sys.maxsize)  # payload·manifest 열이 기본 한도보다 길다
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def bundle_policy(manifest):
    """묶음 manifest → (모델별 임계값, 결합 모델 순서, overlap_policy). bundle.FusionBundle.load_context와 같은 값."""
    thresholds = {m["name"]: m["threshold"] for m in manifest["models"]}
    fusion = manifest["fusion"]
    return thresholds, [m["name"] for m in fusion["models"]], fusion.get("overlap_policy", "skip")


def score_rows(window_score, job_id, capture_id):
    """작업 하나의 창 점수 행 → build_incidents가 받는 dict(capture_id, asset_id, role, window_start, score)와 모델·split."""
    return [{"capture_id": capture_id, "model_name": r["model_name"], "asset_id": r["asset_id"], "role": r["role"],
             "window_start": int(parse_db_time(r["window_start"])), "split": r["split"], "score": float(r["score"]),
             "is_candidate": is_true(r["is_candidate"])}
            for r in window_score if int(r["job_id"]) == job_id]


def rebuild_queue(rows, thresholds, names, overlap_policy, capture_sha, skip_splits=(EDGE,)):
    """bundle.FusionBundle.build_queue와 같은 계산: 모델별 사건 큐 → 결합 큐. skip_splits의 창은 큐에서 뺀다."""
    queues = []
    for name in names:
        day = [r for r in rows if r["model_name"] == name and r["split"] not in skip_splits]
        queues.append(rank_queue(build_incidents(day, thresholds[name], capture_sha)))
    fused, _ = fuse(queues, names, overlap_policy)
    return [{"rank": k, "incident_id": i.incident_id, "asset_id": i.asset_id, "role": i.role,
             "windows": tuple(i.windows)} for k, i in enumerate(fused, 1)]


def stored_queue(incidents, incident_windows, job_id):
    """DB에 저장된 작업의 결합 큐(순위 순서). 모양은 rebuild_queue와 같다."""
    wins = defaultdict(list)
    for r in incident_windows:
        if int(r["job_id"]) == job_id:
            wins[r["incident_id"]].append(int(parse_db_time(r["window_start"])))
    rows = [{"rank": int(r["queue_rank"]), "incident_id": r["incident_id"], "asset_id": r["asset_id"],
             "role": r["role"], "windows": tuple(sorted(wins[r["incident_id"]]))}
            for r in incidents if int(r["job_id"]) == job_id]
    return sorted(rows, key=lambda r: r["rank"])


def queue_differences(rebuilt, stored):
    """두 큐의 (순위, 사건 ID, 창) 차이 목록. 비면 같다."""
    diffs = []
    if len(rebuilt) != len(stored):
        diffs.append(f"사건 수: 다시 만든 큐 {len(rebuilt)}, DB {len(stored)}")
    for a, b in zip(rebuilt, stored):
        if (a["rank"], a["incident_id"], a["windows"]) != (b["rank"], b["incident_id"], b["windows"]):
            diffs.append(f"{a['rank']}위: 다시 만든 큐 {a['incident_id']} 창 {list(a['windows'])}, "
                         f"DB {b['rank']}위 {b['incident_id']} 창 {list(b['windows'])}")
    return diffs


def is_labeled(incident_role, asset_id, window, windows):
    return incident_role == ORIGINATOR and (asset_id, window) in windows


def compare_queues(before, after, windows):
    """규칙 전후 큐 비교. windows: 라벨 대상 (자산, 창) 집합(originator 기준)."""
    after_by_key = {(i["incident_id"], i["windows"]): i for i in after}
    before_keys = {(i["incident_id"], i["windows"]) for i in before}
    removed, scope, other, ranks = [], [], [], []
    for inc in before:
        same = after_by_key.get((inc["incident_id"], inc["windows"]))
        if same:
            ranks.append({"incident_id": inc["incident_id"], "before": inc["rank"], "after": same["rank"]})
            continue
        labeled = [w for w in inc["windows"] if is_labeled(inc["role"], inc["asset_id"], w, windows)]
        into = [{"rank": a["rank"], "incident_id": a["incident_id"], "windows": list(a["windows"])} for a in after
                if (a["asset_id"], a["role"]) == (inc["asset_id"], inc["role"]) and set(a["windows"]) & set(inc["windows"])]
        item = {"incident_id": inc["incident_id"], "before_rank": inc["rank"], "windows": list(inc["windows"]),
                "labeled_windows": labeled, "after": into}
        if labeled and len(labeled) == len(inc["windows"]):
            removed.append(item)
        elif labeled:
            item["kind"] = "split" if len(into) > 1 else ("shrunk" if into else "gone")
            scope.append(item)
        else:
            other.append(item)
    new = [{"rank": a["rank"], "incident_id": a["incident_id"], "windows": list(a["windows"])} for a in after
           if (a["incident_id"], a["windows"]) not in before_keys]
    moved = [r for r in ranks if r["after"] != r["before"]]
    return {
        "incidents_before": len(before), "incidents_after": len(after),
        "removed": removed, "scope_changed": scope, "other_changed": other, "new_or_changed_after": new,
        "unchanged": len(ranks), "rank_changes": moved,
        "rank_moved_up": sum(r["after"] < r["before"] for r in moved),
        "rank_moved_down": sum(r["after"] > r["before"] for r in moved),
    }


def downstream_estimate(capture_id, jobs, incidents, incident_windows, deliveries, reports, windows):
    """그 캡처의 모든 성공 작업에서, 창이 전부 라벨 대상인 사건에 붙어 있던 Slack 행·LLM 보고서 수(추정)."""
    job_ids = {int(j["job_id"]) for j in jobs if j["capture_id"] == capture_id and j["status"] == "succeeded"}
    wins = defaultdict(list)
    for r in incident_windows:
        if int(r["job_id"]) in job_ids:
            wins[(int(r["job_id"]), r["incident_id"])].append(int(parse_db_time(r["window_start"])))
    gone = set()
    for r in incidents:
        key = (int(r["job_id"]), r["incident_id"])
        if key[0] in job_ids and wins[key] and all(is_labeled(r["role"], r["asset_id"], w, windows) for w in wins[key]):
            gone.add(key)
    slack = [d for d in deliveries if (int(d["job_id"]), d["incident_id"]) in gone]
    reps = [r for r in reports if (int(r["job_id"]), r["incident_id"]) in gone]
    return {
        "note": "추정: 그날 전체 conn.log로 정한 라벨 창을 모든 작업의 사건 창에 대 본 값이다. 이만큼은 생기지 않았을 것이라는 참고값이다",
        "jobs": len(job_ids), "incident_rows_all_windows_labeled": len(gone),
        "distinct_incident_ids": len({k[1] for k in gone}),
        "slack_rows": sum(not d["report_version"].startswith("status:") for d in slack),
        "slack_status_rows": sum(d["report_version"].startswith("status:") for d in slack),
        "llm_reports": sum(r["report_kind"] == "llm" for r in reps),
        "template_reports": sum(r["report_kind"] == "template" for r in reps),
    }


def unit_ranks(queue, unit, attack):
    return [{"rank": i["rank"], "incident_id": i["incident_id"], "windows": len(i["windows"]),
             "attack_windows": len(set(i["windows"]) & attack)}
            for i in queue if (i["asset_id"], i["role"]) == (unit["asset"], unit["role"]) and set(i["windows"]) & attack]


def episode_table(config, queues):
    """에피소드·당사자 단위마다 공격 창을 담은 사건의 전후 순위. queues: {캡처: (전, 후, 라벨 창, 작업)}."""
    out = []
    for ep in config["episodes"]:
        cap = episode_capture(ep)
        if cap not in queues:
            continue
        before, after, windows, job_id = queues[cap]
        attack = set(attack_windows(ep))
        for unit in ep["expected_units"]:
            out.append({
                "episode_id": ep["episode_id"], "scenario": ep["scenario"], "run": ep["run"], "capture_id": cap,
                "job_id": job_id, "asset": unit["asset"], "role": unit["role"],
                "attack_windows": len(attack),
                "attack_windows_labeled": sum(is_labeled(unit["role"], unit["asset"], w, windows) for w in attack),
                "before": unit_ranks(before, unit, attack), "after": unit_ranks(after, unit, attack),
                "queue_before": len(before), "queue_after": len(after),
            })
    return out


def baseline_stats(silver_conn_dir, assets_path, capture_id, window_seconds, limit):
    """상한의 출처 재현: 캡처의 점수화 대상 originator 창마다 호스트가 아닌 주소행 연결 수의 분포. 자료가 없으면 None.

    호스트행 연결이 섞인 창과 0인 창도 센다(설정 max_connections_source.measure).
    """
    part = Path(silver_conn_dir) / f"capture_id={capture_id}"
    if not part.exists():
        return None
    import pandas as pd

    conn = pd.read_parquet(part, columns=["orig_h", "resp_h", "write_ts"])
    networks = load_networks([assets_path])
    counts = count_connections(conn.itertuples(index=False, name=None), networks, window_seconds)
    scored = [v for k, v in counts.items() if is_scored_asset(k[0], networks)]
    non_host = [n for n, _ in scored]
    return {"silver": project_path(part), "assets": file_record(assets_path), "capture_id": capture_id,
            "connections": len(conn), "originator_windows": len(scored),
            "non_host_only_windows": sum(1 for n, host in scored if host == 0 and n > 0),
            "windows_with_non_host": sum(1 for n in non_host if n > 0),
            "median": statistics.median(non_host), "p99": percentile(non_host, 99), "max": max(non_host),
            "config_max_connections": limit, "max_equals_config": max(non_host) == limit}


def over_limit_kept(rows, over):
    """상한을 넘어 큐에 남긴 창: 라벨이 붙을 자리(originator, capture_edge 아님)인데 연결 수가 상한보다 많은 (자산, 창).

    capture_edge 창은 원래 큐에서 빠지므로 세지 않는다. rows는 규칙 전 창 점수 행(모델 행 셋을 하나로 센다).
    """
    return {(r["asset_id"], r["window_start"]) for r in rows if r["role"] == ORIGINATOR and r["split"] != EDGE
            and (r["asset_id"], r["window_start"]) in over}


def window_consistency(rows, observed, networks):
    """conn.log의 (점수화 대상 출발 주소, 창)과 작업의 originator 창이 같은지. 다르면 다른 입력이다."""
    scored = {(r["asset_id"], r["window_start"]) for r in rows if r["role"] == ORIGINATOR}
    from_conn = {k for k in observed if is_scored_asset(k[0], networks)}
    return {"job_originator_windows": len(scored), "conn_originator_windows": len(from_conn),
            "missing_in_conn": sorted(scored - from_conn)[:5], "missing_in_job": sorted(from_conn - scored)[:5],
            "same": scored == from_conn}


def ranks_text(items):
    return ", ".join(f"{i['rank']}위({i['windows']}창)" for i in items) or "없음"


def render_markdown(result):
    lines = ["# 큐 자격 규칙 전후 측정", "",
             f"규칙: `{result['rule']['config_id']}` (라벨 `{result['rule']['label']}`). 입력: `{result['export_dir']}`.",
             "", "## 재현 확인", "",
             "| 캡처 | 작업 | 묶음 | 사건(DB) | 재현 | conn 창 대조 |", "| --- | --- | --- | --- | --- | --- |"]
    for c in result["captures"]:
        lines.append(f"| {c['capture_id']} | {c['job_id']} | {c['bundle_id']} | {c['stored_incidents']} | "
                     f"{'같음' if not c['reproduction_differences'] else '다름'} | "
                     f"{'같음' if c['window_consistency']['same'] else '다름'} |")
    b = result.get("baseline")
    if b:
        lines += ["", "## 상한의 출처 재현", "",
                  f"{b['capture_id']} originator 창 {b['originator_windows']}개, 호스트가 아닌 주소행 연결만 있는 창 "
                  f"{b['non_host_only_windows']}개. 창당 호스트가 아닌 주소행 연결 수: 중앙 {b['median']}, p99 {b['p99']:g}, "
                  f"최대 {b['max']}. 설정 상한 {b['config_max_connections']}과 최대가 "
                  f"{'같다' if b['max_equals_config'] else '다르다'}."]
    elif result.get("baseline_skipped"):
        lines += ["", f"상한의 출처 재현: 건너뜀({result['baseline_skipped']})."]
    lines += ["", "## 캡처별 전후", "",
              f"상한: 창당 호스트가 아닌 주소행 연결 {result['rule']['max_connections']}개 이하만 뺀다.", "",
              "| 캡처 | 사건 전 | 사건 후 | 뺀 창 | 상한 넘어 남긴 창 | 사라진 사건 | 범위 바뀜(줄어듦/쪼개짐) | 그 밖 바뀜 | 새로 생김 | 순위 오름/내림 | "
              "Slack 행·LLM 보고서(추정, 전체 작업) |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for c in result["captures"]:
        q, d = c["comparison"], c["downstream_estimate"]
        kinds = defaultdict(int)
        for s in q["scope_changed"]:
            kinds[s["kind"]] += 1
        lines.append(f"| {c['capture_id']} | {q['incidents_before']} | {q['incidents_after']} | {c['excluded_windows']} | "
                     f"{c['over_limit_kept_windows']} | "
                     f"{len(q['removed'])} | {len(q['scope_changed'])}({kinds['shrunk']}/{kinds['split']}) | "
                     f"{len(q['other_changed'])} | {len(q['new_or_changed_after'])} | "
                     f"{q['rank_moved_up']}/{q['rank_moved_down']} | {d['slack_rows']}·{d['llm_reports']} |")
    lines += ["", "Slack 행은 status:* 행을 뺀 수다. 추정 열은 그날 전체 conn.log로 정한 라벨 창을 모든 작업의 사건 창에 "
              "대 본 값으로, \"이만큼은 생기지 않았을 것\"의 참고값이다.", "",
              "## 범위가 바뀐 사건", ""]
    for c in result["captures"]:
        for s in c["comparison"]["scope_changed"]:
            after = ", ".join(f"{a['rank']}위 {a['incident_id']}({len(a['windows'])}창)" for a in s["after"]) or "없음"
            lines.append(f"- {c['capture_id']} 전 {s['before_rank']}위 `{s['incident_id']}` 창 {len(s['windows'])}개 중 "
                         f"{len(s['labeled_windows'])}개 뺌 → {s['kind']}: {after}")
    lines += ["", "## 공격 에피소드 전후 순위", "",
              "| 에피소드 | 종류 | 실행 | 단위 | 공격 창 | 라벨 붙은 공격 창 | 전 순위(큐 크기) | 후 순위(큐 크기) |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for e in result["episodes"]:
        lines.append(f"| {e['episode_id']} | {e['scenario']} | {e['run']} | {e['asset']} {e['role']} | "
                     f"{e['attack_windows']} | {e['attack_windows_labeled']} | "
                     f"{ranks_text(e['before'])} ({e['queue_before']}) | {ranks_text(e['after'])} ({e['queue_after']}) |")
    lines.append("")
    return "\n".join(lines)


def conn_inputs(capture_id):
    """캡처의 conn.log 파일 기록 묶음(파일 수와 해시 묶음의 해시)."""
    paths = sorted((ZEEK_ROOT / capture_id).glob("*/conn.log"))
    digest = hashlib.sha256("\n".join(f"{p.parent.name} {sha256(p)}" for p in paths).encode()).hexdigest()
    return {"capture_id": capture_id, "dir": project_path(ZEEK_ROOT / capture_id), "conn_logs": len(paths),
            "sha256_of_folder_and_sha256_lines": digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--export-dir", type=Path, default=EXPORT)
    parser.add_argument("--out-dir", type=Path, default=OUT)
    parser.add_argument("--baseline-silver", type=Path,
                        help="상한 출처 재현용 Silver conn 폴더(예: outputs/silver/conn_v1/conn). 주지 않으면 건너뛴다")
    parser.add_argument("--baseline-assets", type=Path, default=PROJECT_ROOT / "configs" / "assets.cic-ids-2017.v1.json")
    parser.add_argument("--baseline-capture", default="cic17-mon")
    args = parser.parse_args()

    tables = {t: read_csv(args.export_dir / f"{t}.csv") for t in TABLES}
    rule = load_config(RULE)
    networks = load_networks([ASSETS])
    w = time_windows.load_window_config(time_windows.PROJECT_CONFIG)["window_seconds"]
    manifests = {r["bundle_id"]: json.loads(r["manifest"]) for r in tables["model_bundle"]}
    truth = load_truth(TRUTH)

    results, queues, failed = [], {}, False
    for cap in CAPTURES:
        job = last_job(tables["scoring_job"], cap)
        job_id = int(job["job_id"])
        thresholds, names, policy = bundle_policy(manifests[job["bundle_id"]])
        files = [{"sha256": f["file_sha256"].strip()} for f in tables["ingest_file"]
                 if f["capture_id"] == cap and f["status"] in ("zeek_done", "pipeline_done")]
        capture_sha = {cap: files_sha256(files)}
        rows = score_rows(tables["window_score"], job_id, cap)
        stored = stored_queue(tables["incident"], tables["incident_window"], job_id)
        before = rebuild_queue(rows, thresholds, names, policy, capture_sha)
        diffs = queue_differences(before, stored)
        conns = [(r["orig_h"], r["resp_h"], r["write_ts"]) for r in read_capture_conn(ZEEK_ROOT, cap)]
        windows, over, observed = scan_connections(conns, networks, w, rule["max_connections"])
        consistency = window_consistency(rows, observed, networks)
        labeled = label_rows(rows, windows, rule["label"])
        after = rebuild_queue(labeled, thresholds, names, policy, capture_sha, (EDGE, rule["label"]))
        excluded = {(r["asset_id"], r["window_start"]) for r in labeled if r["split"] == rule["label"]}
        kept = over_limit_kept(rows, over)
        results.append({
            "capture_id": cap, "job_id": job_id, "bundle_id": job["bundle_id"], "overlap_policy": policy,
            "pcap_sha256": capture_sha[cap], "files": len(files), "connections": len(conns),
            "stored_incidents": len(stored), "reproduction_differences": diffs,
            "window_consistency": consistency,
            "non_host_only_windows_all_origins": len(windows),
            "excluded_windows": len(excluded), "over_limit_kept_windows": len(kept),
            "over_limit_kept": sorted([a, t] for a, t in kept),
            "excluded_windows_by_asset": {a: sum(1 for x, _ in excluded if x == a) for a in sorted({x for x, _ in excluded})},
            "comparison": compare_queues(before, after, windows),
            "downstream_estimate": downstream_estimate(cap, tables["scoring_job"], tables["incident"],
                                                       tables["incident_window"], tables["slack_delivery"],
                                                       tables["agent_report"], windows),
        })
        queues[cap] = (before, after, windows, job_id)
        state = "같음" if not diffs else f"다름 {len(diffs)}건"
        print(f"{cap}: 작업 {job_id}({job['bundle_id']}) 재현 {state}, conn 창 대조 "
              f"{'같음' if consistency['same'] else '다름'}, 사건 {len(before)} → {len(after)}, 뺀 창 {len(excluded)}, "
              f"상한 넘어 남긴 창 {len(kept)}",
              flush=True)
        for d in diffs[:10]:
            print(f"  {d}")
        if not consistency["same"]:
            print(f"  conn 창 대조: {consistency}")
        failed = failed or bool(diffs) or not consistency["same"]

    if failed:
        print("재현 확인 실패: 결과를 쓰지 않는다", file=sys.stderr)
        return 1

    baseline, skipped = None, None
    if args.baseline_silver:
        try:
            baseline = baseline_stats(args.baseline_silver, args.baseline_assets, args.baseline_capture, w,
                                      rule["max_connections"])
        except ImportError as e:
            skipped = f"pandas 없음: {e}"
        if baseline is None and skipped is None:
            skipped = f"자료 없음: {project_path(args.baseline_silver)}/capture_id={args.baseline_capture}"
    else:
        skipped = "--baseline-silver를 주지 않음"
    if baseline:
        print(f"상한 출처({args.baseline_capture}): originator 창 {baseline['originator_windows']}, 중앙 {baseline['median']}, "
              f"p99 {baseline['p99']:g}, 최대 {baseline['max']}, 설정 상한 {rule['max_connections']}과 "
              f"{'같음' if baseline['max_equals_config'] else '다름'}")
    else:
        print(f"상한 출처 재현 건너뜀: {skipped}")

    result = {
        "measurement_version": 1, "export_dir": project_path(args.export_dir),
        "rule": {"config_id": rule["config_id"], "label": rule["label"], "max_connections": rule["max_connections"],
                 **file_record(RULE)},
        "baseline": baseline, "baseline_skipped": skipped,
        "inputs": [file_record(args.export_dir / f"{t}.csv") for t in TABLES]
                  + [file_record(ASSETS), file_record(TRUTH), file_record(time_windows.PROJECT_CONFIG)],
        "conn_inputs": [conn_inputs(cap) for cap in CAPTURES],
        "code": [file_record(p) for p in CODE_FILES],
        "definitions": {
            "job": "캡처에서 status = succeeded인 작업 가운데 job_id가 가장 큰 것",
            "reproduction": "규칙 없이 저장된 창 점수로 다시 만든 결합 큐의 (순위, 사건 ID, 창)이 DB incident·incident_window와 같다",
            "window_consistency": "conn.log의 (점수화 대상 출발 주소, _write_ts 창)과 작업 window_score의 originator 창이 같다",
            "excluded_windows": "라벨이 붙은 originator (자산, 창) 수(capture_edge 제외, 모델 행 셋을 하나로 센다)",
            "over_limit_kept_windows": "연결이 전부 호스트가 아닌 주소행이지만 그 수가 max_connections보다 많아 라벨 없이 큐에 남긴 originator 창 수",
            "removed": "전 큐 사건 가운데 모든 창에 라벨이 붙은 사건",
            "scope_changed": "일부 창에만 라벨이 붙어 범위가 바뀐 사건(shrunk: 후 큐 사건 하나로 줄어듦, split: 둘 이상으로 쪼개짐)",
            "other_changed": "라벨 창이 없는데 같은 사건(ID·창)이 후 큐에 없는 사건(결합·30분 상한으로 다른 사건이 바뀐 영향)",
            "new_or_changed_after": "후 큐 사건 가운데 전 큐에 같은 사건(ID·창)이 없는 것",
            "rank_changes": "전후 같은 사건(ID·창)의 순위 변화",
        },
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "captures": results,
        "episodes": episode_table(truth, queues),
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (args.out_dir / "result.md").write_text(render_markdown(result), encoding="utf-8")
    print(f"written={project_path(args.out_dir)}/result.json, result.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
