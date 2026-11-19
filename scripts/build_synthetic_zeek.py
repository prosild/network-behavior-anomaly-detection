"""합성 APT 패턴을 화~금 Zeek 로그(run-02 사본)에 주입한다(DD-008, configs/synthetic/apt-injection.v1.json).

출력(outputs/synthetic/apt_v1/):
- zeek/<요일>/run-02/: 원래 로그 + 주입 행(_write_ts 순서로 끼워 넣음). 바뀌지 않은 로그는 하드 링크다.
- zeek/<요일>/run-02/run-manifest.json: Silver 빌드가 읽는 형식. 원본 manifest와 설정 해시를 함께 남긴다.
- truth/episodes.json, truth/windows.parquet: 주입한 연결의 uid와 정답 창.
- capture-bounds.json: 합성 캡처 ID에 원래 날의 캡처 경계를 붙인 것.
- manifest.json
원본 CIC-IDS-2017/와 outputs/zeek/는 바꾸지 않는다.
"""

import argparse
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import random
import shutil
import sys

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import synthetic_apt as syn  # noqa: E402
from zeek_ad.provenance import file_record, project_path, sha256  # noqa: E402
from zeek_ad.windows import load_window_config, PROJECT_CONFIG  # noqa: E402

CONFIG = PROJECT_ROOT / "configs" / "synthetic" / "apt-injection.v1.json"
BOUNDS = PROJECT_ROOT / "manifests" / "cic-ids-2017.capture-bounds.v1.json"
CIC_TRUTH = PROJECT_ROOT / "outputs" / "ground_truth" / "cic17_v1" / "windows"
EVENT_INDEX = PROJECT_ROOT / "outputs" / "graphs" / "tgn_v1" / "index.parquet"
NODES = PROJECT_ROOT / "outputs" / "graphs" / "tgn_v1" / "nodes.parquet"
ZEEK = PROJECT_ROOT / "outputs" / "zeek"
LOGS = ["conn", "dns", "ssl", "kerberos", "smb_mapping", "smb_files", "dce_rpc"]
# 패턴 순서: 대상 제약이 있는 것부터 자리를 잡는다.
ORDER = ["lateral_smb", "internal_scan", "beacon_https", "slow_exfil", "dns_tunnel"]


def write_ts_of(line):
    # Zeek JSON 행은 {"_write_ts":값, ...}로 시작한다. 전체를 파싱하지 않고 값만 읽는다.
    return float(line[len('{"_write_ts":'):line.index(",")])


def merge_log(src, dst, rows):
    """원래 행 순서를 지키며, 주입 행을 _write_ts가 더 큰 첫 원래 행 앞에 끼워 넣는다."""
    rows = sorted(rows, key=lambda r: r["_write_ts"])
    k, n = 0, 0
    with open(src, encoding="utf-8") as fin, open(dst, "w", encoding="utf-8") as fout:
        for line in fin:
            while k < len(rows) and rows[k]["_write_ts"] < write_ts_of(line):
                fout.write(json.dumps(rows[k], separators=(",", ":")) + "\n")
                k, n = k + 1, n + 1
            fout.write(line)
            n += 1
        for r in rows[k:]:
            fout.write(json.dumps(r, separators=(",", ":")) + "\n")
            n += 1
    return n


def external_pool(index, top_k):
    """월요일 train 외부 IP가 많이 쓰는 /16 대역 상위 top_k."""
    tr = index[index.split == "train"]
    ips = pd.concat([tr.orig_h, tr.resp_h]).unique()
    pubs = [ip for ip in ips if ipaddress.ip_address(ip).version == 4 and ipaddress.ip_address(ip).is_global]
    counts = Counter(".".join(ip.split(".")[:2]) for ip in pubs)
    return [p for p, _ in counts.most_common(top_k)]


def new_external_ip(rng, prefixes, seen):
    while True:
        ip = f"{rng.choice(prefixes)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        if ip not in seen and ipaddress.ip_address(ip).is_global:
            seen.add(ip)
            return ip


def conflicts(windows, blocked, margin):
    # 같은 (자산, 역할)의 막힌 창과 margin 안에 있으면 충돌이다.
    for asset, role, w in windows:
        for b in blocked.get((asset, role), ()):
            if abs(w - b) <= margin:
                return True
    return False


def place(ctx, cfg, name, day, bounds, blocked, used_attackers, prefixes, seen_ips, w):
    """패턴 하나를 충돌 없는 시각·호스트에 놓는다."""
    p, hosts, sched = cfg["patterns"][name], cfg["hosts"], cfg["schedule"]
    dc = hosts["infrastructure"]["dns_kerberos"]
    lo, hi = float(bounds["packet_time_min"]), float(bounds["packet_time_max"])
    for _ in range(sched["max_tries"]):
        attacker = ctx.rng.choice([h for h in hosts["attackers"] if h not in used_attackers])
        length = p.get("duration_seconds", 3600)
        start = ctx.rng.uniform(lo + sched["edge_margin_seconds"], hi - sched["edge_margin_seconds"] - length)
        ctx.issued, ports = [], dict(ctx.next_port)
        extra = {}
        if name == "lateral_smb":
            targets = ctx.rng.sample([h for h in hosts["windows_targets"] if h != attacker], p["targets"])
            ep, extra = syn.lateral_smb(ctx, attacker, start, p, dc, targets), {"targets": targets}
        elif name == "internal_scan":
            targets = ctx.rng.sample([h for h in hosts["scan_targets"] if h != attacker], p["targets"])
            ep = syn.internal_scan(ctx, attacker, start, p, targets, hosts["linux_hosts"])
            extra = {"targets": targets}
        elif name in ("beacon_https", "slow_exfil"):
            c2, domain = new_external_ip(ctx.rng, prefixes, seen_ips), syn.random_domain(ctx.rng, cfg["external"]["domain_tlds"])
            ep = getattr(syn, name)(ctx, attacker, start, p, dc, c2, domain)
            extra = {"c2_ip": c2, "domain": domain}
        else:
            domain = syn.random_domain(ctx.rng, cfg["external"]["domain_tlds"])
            ep, extra = syn.dns_tunnel(ctx, attacker, start, p, dc, domain), {"domain": domain}
        windows = syn.truth_windows(ep, w)
        if ep.end <= hi - sched["edge_margin_seconds"] and not conflicts(windows, blocked, sched["conflict_margin_seconds"]):
            for asset, role, ws in windows:
                blocked.setdefault((asset, role), []).append(ws)
            used_attackers.add(attacker)
            return ep, extra, windows
        # 실패한 시도의 uid·포트 사용은 되돌린다. 난수 상태는 계속 진행한다(다음 시도가 달라지도록).
        ctx.used_uids.difference_update(ctx.issued)
        ctx.next_port = ports
    sys.exit(f"{day} {name}: {sched['max_tries']}번 안에 충돌 없는 자리를 못 찾았다")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "synthetic" / "apt_v1")
    args = parser.parse_args()
    if args.out.exists():
        sys.exit(f"이미 있다: {project_path(args.out)}")

    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    w = load_window_config(PROJECT_CONFIG)["window_seconds"]
    bounds = {c["capture_id"]: c for c in json.loads(BOUNDS.read_text(encoding="utf-8"))["captures"]}
    cic = pd.read_parquet(CIC_TRUTH)
    index = pd.read_parquet(EVENT_INDEX, columns=["uid", "split", "orig_h", "resp_h"])
    prefixes = external_pool(index, cfg["external"]["prefix_top_k"])
    seen_ips = set(pd.read_parquet(NODES).ip)
    used_uids = set(index.uid)

    tmp = args.out.with_name(args.out.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    (tmp / "truth").mkdir(parents=True)
    episodes, truth_rows, run_manifests, synth_bounds = [], [], [], []
    for day, spec in cfg["days"].items():
        src_cap = spec["source_capture"]
        rng = random.Random(f"{cfg['seed']}:{day}")
        ctx = syn.Context(rng, {k: v for k, v in cfg["write_delay_seconds"].items() if k != "note"}, used_uids)
        # CIC 정답 창은 그날의 막힌 자리다.
        day_cic = cic[cic.capture_id == src_cap]
        blocked = {}
        for r in day_cic.itertuples(index=False):
            blocked.setdefault((r.asset_id, r.role), []).append(int(r.window_start))
        used_attackers, rows = set(), {log: [] for log in LOGS}
        for name in ORDER:
            ep, extra, windows = place(ctx, cfg, name, day, bounds[src_cap], blocked, used_attackers, prefixes, seen_ips, w)
            eid = f"{day}-{name}"
            for log, lr in ep.logs.items():
                rows[log] += lr
            episodes.append({"episode_id": eid, "capture_id": day, "pattern": name, "status": "confirmed",
                             "attacker": ep.attacker, **extra, "start_ts": round(ep.start, 6), "end_write_ts": ep.end,
                             "conn_uids": [r["uid"] for r in ep.logs["conn"]],
                             "rows": {log: len(lr) for log, lr in ep.logs.items()}})
            truth_rows += [{"capture_id": day, "episode_id": eid, "asset_id": a, "role": role, "window_start": ws}
                           for a, role, ws in sorted(windows)]

        src_dir, dst_dir = ZEEK / spec["zeek_day"] / cfg["source_zeek_run"], tmp / "zeek" / spec["zeek_day"] / cfg["source_zeek_run"]
        dst_dir.mkdir(parents=True)
        src_manifest = json.loads((src_dir / "run-manifest.json").read_text(encoding="utf-8"))
        outputs = []
        for o in src_manifest["outputs"]:
            log = o["name"].removesuffix(".log")
            if log in rows and rows[log]:
                n = merge_log(src_dir / o["name"], dst_dir / o["name"], rows[log])
                assert n == o["rows"] + len(rows[log]), o["name"]
                outputs.append({"name": o["name"], "rows": n, "injected_rows": len(rows[log]),
                                "size_bytes": (dst_dir / o["name"]).stat().st_size, "sha256": sha256(dst_dir / o["name"])})
            else:
                os.link(src_dir / o["name"], dst_dir / o["name"])  # 바뀌지 않은 로그는 하드 링크
                outputs.append({**o, "injected_rows": 0})
        manifest = {"run_manifest_version": 1, "synthetic": {"config": file_record(CONFIG), "capture_id": day,
                                                              "source_run_manifest": file_record(src_dir / "run-manifest.json")},
                    **{k: v for k, v in src_manifest.items() if k not in ("outputs",)}, "outputs": outputs}
        (dst_dir / "run-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        run_manifests.append(dst_dir / "run-manifest.json")
        synth_bounds.append({**bounds[src_cap], "capture_id": day, "source_capture": src_cap})
        print(day, {o["name"]: o["injected_rows"] for o in outputs if o["injected_rows"]})

    (tmp / "truth" / "episodes.json").write_text(json.dumps({"episodes": episodes}, ensure_ascii=False, indent=2) + "\n",
                                                  encoding="utf-8")
    truth = pd.DataFrame(truth_rows)
    truth.to_parquet(tmp / "truth" / "windows.parquet", index=False)
    (tmp / "capture-bounds.json").write_text(json.dumps({"captures": synth_bounds}, indent=2) + "\n", encoding="utf-8")

    # 검사: 정답 창이 에피소드끼리 겹치지 않고, CIC 정답 창과도 겹치지 않는다. 주입 uid가 원래 uid와 다르다.
    cic_keys = {(r.capture_id, r.asset_id, r.role, int(r.window_start)) for r in cic.itertuples(index=False)}
    syn_keys = [(cfg["days"][r.capture_id]["source_capture"], r.asset_id, r.role, int(r.window_start))
                for r in truth.itertuples(index=False)]
    all_uids = [u for e in episodes for u in e["conn_uids"]]
    checks = {"no_overlap_between_episodes": len(syn_keys) == len(set(syn_keys)),
              "no_overlap_with_cic": not (set(syn_keys) & cic_keys),
              "uids_unique_and_new": len(all_uids) == len(set(all_uids)) and not (set(all_uids) & set(index.uid))}
    if not all(checks.values()):
        sys.exit(f"검사 실패: {checks}")
    (tmp / "manifest.json").write_text(json.dumps({
        "config": file_record(CONFIG), "code": [file_record(PROJECT_ROOT / "zeek_ad" / "synthetic_apt.py"),
                                                file_record(Path(__file__).resolve())],
        "inputs": [file_record(BOUNDS), file_record(EVENT_INDEX), file_record(NODES),
                   file_record(PROJECT_ROOT / "outputs" / "ground_truth" / "cic17_v1" / "manifest.json")],
        "external_prefixes": prefixes, "episodes": len(episodes), "truth_windows": len(truth), "checks": checks,
        "run_manifests": [project_path(p).replace(tmp.name, args.out.name) for p in run_manifests],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, args.out)
    print(f"episodes={len(episodes)} truth_windows={len(truth)} checks={checks} -> {project_path(args.out)}")


if __name__ == "__main__":
    main()
