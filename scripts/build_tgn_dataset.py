"""TGN 학습용 시간 그래프 데이터(DD-007 2단계). 입력: outputs/events/tgn_v1. 설정: configs/models/tgn.v1.json(data 절).

출력(outputs/graphs/tgn_v1/):
- events.npz: 시간순 이벤트 텐서(src, dst, t, cat, hist, num, dns_weight). pickle 없이 읽는다.
- index.parquet: 같은 순서의 평가 키(uid, capture_id, window_start, split, orig_h, resp_h, 점수 대상 여부).
- nodes.parquet: IP → 번호와 노드 특징(주소만으로 만든 해시·표시).
- encoding.json: 어휘와 표준화 값(월요일 train으로만 적합).
"""

import argparse
import json
from pathlib import Path
import sys

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import assets  # noqa: E402
from zeek_ad.provenance import file_record, project_path, sha256  # noqa: E402
from zeek_ad.tgn_data import (  # noqa: E402
    build_vocab, direction, encode, encode_history, entropy, http_status_class, ip_flags, ip_hash_features,
    port_group, ssh_auth, ssl_state,
)

CONFIG = PROJECT_ROOT / "configs" / "models" / "tgn.v1.json"
EVENTS = PROJECT_ROOT / "outputs" / "events" / "tgn_v1"
CAPTURE_ORDER = ["cic17-mon", "cic17-tue", "cic17-wed", "cic17-thu", "cic17-fri"]
TRAIN_CAPTURE = "cic17-mon"


def none_if_na(v):
    return None if v is None or (isinstance(v, float) and np.isnan(v)) or v is pd.NA else v


def categorical_columns(df, internal):
    """이벤트마다 범주 값(문자열 또는 None)을 만든다. 같은 값 조합은 한 번만 계산한다.

    열 타입은 object로 고정한다. pandas 3은 문자열·None 목록을 문자열 타입으로 바꾸면서 None을 NaN(실수)으로 만든다.
    그러면 어휘를 정렬할 때 문자열과 실수가 섞여 실패한다. pandas 2.3.3(잠금 파일 버전)에서는 원래 object였다.
    """
    cols = {}
    cols["direction"] = [direction(internal[o], internal[r]) for o, r in zip(df.orig_h, df.resp_h)]
    pg = df[["proto", "resp_p"]].drop_duplicates()
    pg_map = {(p, q): port_group(p, none_if_na(q)) for p, q in pg.itertuples(index=False)}
    cols["port_group"] = [pg_map[(p, q)] for p, q in zip(df.proto, df.resp_p)]
    for col in ["proto", "service", "conn_state", "dns_qtype", "dns_rcode", "http_method", "smb_share_type",
                "krb_request_type", "dce_operation"]:
        cols[col] = [none_if_na(v) for v in df[col]]
    cols["http_status_class"] = [http_status_class(none_if_na(v)) for v in df.http_status_max]
    cols["ssl_state"] = [ssl_state(none_if_na(a), none_if_na(b), none_if_na(c), none_if_na(d)) for a, b, c, d in
                         zip(df.ssl_version, df.ssl_established, df.ssl_sni, df.ssl_sni_matches_cert)]
    cols["ssl_version"] = [none_if_na(v) for v in df.ssl_version]
    cols["ssh_auth"] = [ssh_auth(none_if_na(v)) for v in df.ssh_auth_success]
    return pd.DataFrame({c: pd.Series(v, index=df.index, dtype=object) for c, v in cols.items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "graphs" / "tgn_v1")
    # 합성 캡처(DD-008): --events outputs/events/tgn_v1 outputs/synthetic/apt_v1/events/tgn_v1
    #   --captures cic17-mon syn1-tue syn1-wed syn1-thu syn1-fri. 월요일 train은 원래 이벤트에서 온다.
    parser.add_argument("--events", type=Path, nargs="+", default=[EVENTS])
    parser.add_argument("--captures", nargs="+", default=CAPTURE_ORDER, help="이 순서로 이어 붙인다")
    # 실습망(DD-012)은 configs/assets.lab.v1.json. 월요일 CIC 대역과 함께 주므로 둘을 합친다. 기본값은 CIC 설정 하나(기존 동작).
    parser.add_argument("--assets", type=Path, nargs="+", default=[assets.PROJECT_CONFIG])
    args = parser.parse_args()
    if TRAIN_CAPTURE not in args.captures:
        sys.exit(f"인코딩을 적합할 {TRAIN_CAPTURE}가 --captures에 없다")
    if args.out.exists():
        sys.exit(f"이미 있다: {project_path(args.out)}")
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    d = config["data"]

    parts = []
    for events_dir in args.events:
        part = pd.read_parquet(events_dir / "events")
        part["capture_id"] = part["capture_id"].astype(str)
        parts.append(part[part.capture_id.isin(args.captures)])
    # 열 타입을 첫 이벤트 표(월요일이 든 원래 표)에 맞춘다. 실습망 하루처럼 작은 표는 한 번도 값이 없는 열이
    # object(전부 None)로 읽혀, 이어 붙이면 월요일 열까지 object가 되고 결측 표현이 섞인다(DD-012).
    for part in parts[1:]:
        for c in part.columns:
            if c in parts[0].columns and c != "capture_id" and part[c].dtype != parts[0][c].dtype:
                part[c] = part[c].astype(parts[0][c].dtype)
    df = pd.concat(parts, ignore_index=True)
    if sorted(df.capture_id.unique()) != sorted(args.captures):
        sys.exit(f"이벤트에 없는 캡처가 있다: {sorted(set(args.captures) - set(df.capture_id))}")
    df["_cap"] = df.capture_id.map({c: i for i, c in enumerate(args.captures)})
    df = df.sort_values(["_cap", "write_ts", "source_row_number"], kind="stable").reset_index(drop=True)
    is_train = ((df.capture_id == TRAIN_CAPTURE) & (df.split == "train")).to_numpy()

    # 노드: 모든 IP에 번호를 준다. 번호는 정보가 아니고, 메모리는 모두 0에서 시작한다.
    networks = assets.load_networks(args.assets)
    ips = sorted(set(df.orig_h) | set(df.resp_h))
    node_id = {ip: i for i, ip in enumerate(ips)}
    scored = {ip: assets.is_scored_asset(ip, networks) for ip in ips}
    nf = d["node_features"]
    node_x = np.array([ip_hash_features(ip, nf["ip_hash_dim"]) + ip_flags(ip, networks, scored[ip]) for ip in ips],
                      dtype=np.float32)
    internal = {ip: bool(node_x[i, nf["ip_hash_dim"]]) for i, ip in enumerate(ips)}

    # 범주: 월요일 train으로 어휘를 만들고 번호로 바꾼다.
    cats = categorical_columns(df, internal)
    vocabs = {c: build_vocab(cats.loc[is_train, c], d["vocab_min_count"]) for c in d["categorical"]}
    cat = np.stack([np.array([encode(v, vocabs[c]) for v in cats[c]], dtype=np.int32) for c in d["categorical"]], 1)
    hist = np.array([encode_history(none_if_na(h), d["history_max_len"]) for h in df.history], dtype=np.int8)

    # 수치: 로그가 없으면 0. log1p 묶음은 log1p 뒤에, 모든 수치는 train 평균·표준편차로 표준화한다.
    num = pd.DataFrame(index=df.index)
    for c in d["numeric_log1p"]:
        num[c] = np.log1p(df[c].astype(float).fillna(0).clip(lower=0))
    queries = df.dns_query.dropna().unique()
    ent = {q: entropy(q) for q in queries}
    num["dns_query_entropy"] = [ent.get(q, 0.0) if isinstance(q, str) else 0.0 for q in df.dns_query]
    num["http_uri_special_max"] = df.http_uri_special_max.astype(float).fillna(0)
    num["duration_missing"] = df.duration.isna().astype(float)
    num = num[d["numeric_log1p"] + d["numeric_raw"]]
    mean = num[is_train].mean()
    # 희소 특징(NTLM, SMB 등)은 train 표준편차가 0.01 수준이라, 한 번만 나와도 값이 100을 넘어 복원 손실을 지배한다.
    # 그래서 표준편차에 하한을 둔다(log1p 척도에서 1). 0인 특징도 하한으로 처리된다.
    std = num[is_train].std(ddof=0).clip(lower=d["numeric_std_floor"])
    num_arr = ((num - mean) / std).to_numpy(dtype=np.float32)

    is_dns = ((df.proto == "udp") & (df.resp_p == 53)) | df.service.fillna("").str.contains("dns")
    dns_weight = np.where(is_dns, d["dns_loss_weight"], 1.0).astype(np.float32)
    t0 = int(np.floor(df.write_ts.min()))
    t = np.floor(df.write_ts.to_numpy() - t0).astype(np.int64)  # TGN 메모리는 정수 시각을 쓴다(초)

    args.out.mkdir(parents=True)
    np.savez(args.out / "events.npz", src=df.orig_h.map(node_id).to_numpy(np.int64),
             dst=df.resp_h.map(node_id).to_numpy(np.int64), t=t, cat=cat, hist=hist, num=num_arr,
             dns_weight=dns_weight, node_x=node_x)
    index = df[["uid", "capture_id", "window_start", "split", "orig_h", "resp_h"]].assign(
        orig_scored=df.orig_h.map(scored), resp_scored=df.resp_h.map(scored), is_dns=is_dns.to_numpy())
    index.to_parquet(args.out / "index.parquet", index=False)
    pd.DataFrame({"ip": ips, "node": range(len(ips)), "scored": [scored[i] for i in ips]}).to_parquet(
        args.out / "nodes.parquet", index=False)
    (args.out / "encoding.json").write_text(json.dumps({
        "categorical": d["categorical"], "vocab_sizes": {c: len(v) + 2 for c, v in vocabs.items()}, "vocabs": vocabs,
        "history_vocab_size": 27, "numeric": list(num.columns), "numeric_mean": mean.round(8).to_dict(),
        "numeric_std": std.round(8).to_dict(), "numeric_rule": "모든 수치를 train 평균과 max(train 표준편차, numeric_std_floor)로 표준화(log1p 묶음은 log1p 뒤)",
        "node_feature_dim": int(node_x.shape[1]), "t0_epoch_seconds": t0,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    unknown = {c: float((cat[~is_train, i] == 1).mean()) for i, c in enumerate(d["categorical"])}
    summary = {"events": len(df), "train_events": int(is_train.sum()), "nodes": len(ips),
               "internal_nodes": int(sum(internal.values())), "scored_nodes": int(sum(scored.values())),
               "dns_share_train": float(is_dns[is_train].mean()), "unknown_rate_non_train": unknown,
               "train_num_mean_abs_max": float(np.abs(num_arr[is_train].mean(0)).max())}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    (args.out / "manifest.json").write_text(json.dumps({
        "dataset": "tgn_graph_v1", "config": file_record(CONFIG),
        "assets": [file_record(p) for p in args.assets],
        "events_manifests": [file_record(e / "manifest.json") for e in args.events], "captures": args.captures,
        "code": [file_record(Path(__file__).resolve()), file_record(PROJECT_ROOT / "zeek_ad" / "tgn_data.py")],
        "outputs": [{"path": project_path(p), "sha256": sha256(p)} for p in sorted(args.out.glob("*")) if p.is_file()],
        "summary": summary,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
