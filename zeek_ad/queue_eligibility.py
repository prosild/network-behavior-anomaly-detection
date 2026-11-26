"""조사 큐에 오를 자격 규칙(configs/worker/queue-eligibility.v1.json, 사용자 결정 2026-11-26).

그 자산이 그 창에 건 연결이 전부 호스트가 아닌 주소(브로드캐스트·멀티캐스트)로 갔고, 그 연결 수가 설정의 상한
(max_connections) 이하인 originator 창은 점수는 남기되 split을 non_host_only로 바꾸고 조사 큐에서 뺀다.
상한을 넘는 창(한 호스트가 브로드캐스트만 쏟아내는 폭주)은 라벨 없이 지금처럼 모델 점수로 큐에 오른다. 캡처 첫·끝 창(capture_edge)을 빼는 것과 같은 자리다.
탐지기가 아니다. 모델·특징·묶음(zeek_ad/bundle.py)은 그대로이고, worker가 build_queue에 넘기는 표만 줄인다.

- 창 배정은 Gold와 같다: 연결의 _write_ts를 windows.window_start로 내린다(zeek_ad/role_windows.py).
- 연결 자료는 그 리비전의 Silver(silver/conn_v1)다. Gold v1 창은 Silver 연결을 자산·역할로 펼쳐 만들므로 같은 행 집합이다.
- 입력 묶음 정의(worker-inputs.json)의 set에 queue_eligibility 항목이 있을 때만 쓴다. 항목이 없는 set(CIC·합성,
  옛 리비전)은 계산과 작업 식별(worker.input_fingerprint)이 예전과 같다.
주소·창 판정과 라벨 적용은 표준 라이브러리만 쓴다. Silver 읽기와 창 점수 표(pandas) 처리만 pandas를 쓴다.
"""

import ipaddress
import json
from pathlib import Path

from zeek_ad.assets import ORIGINATOR, is_scored_asset, load_networks
from zeek_ad.provenance import sha256
from zeek_ad import windows as time_windows

# 설정이 말하는 "호스트가 아닌 주소"의 정의. 코드(is_non_host_address)가 하는 일과 같아야 설정을 받는다.
SUPPORTED_DEFINITION = {
    "internal_network_address": True,
    "internal_broadcast_address": True,
    "limited_broadcast": "255.255.255.255",
    "multicast": True,
}
LIMITED_BROADCAST = ipaddress.ip_address("255.255.255.255")
# 이미 큐에서 빠지는 창. 라벨을 덮어쓰지 않는다(이유가 둘이면 원래 이유를 남긴다).
KEEP_SPLITS = ("capture_edge",)
# 창 라벨로 이미 쓰는 값(windows.label_window, captures 설정의 usage). 새 라벨이 이것과 겹치면 뜻이 섞인다.
RESERVED_LABELS = ("train", "holdout", "split_boundary", "capture_edge", "development", "retrospective_eval", "live")


def load_config(path):
    """규칙 설정을 읽고 코드가 지원하는 정의인지 확인한다."""
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    definition = {k: v for k, v in config["non_host_addresses"].items() if k != "meaning"}
    if definition != SUPPORTED_DEFINITION:
        raise ValueError(f"지원하지 않는 호스트가 아닌 주소 정의: {definition} (지원: {SUPPORTED_DEFINITION})")
    # 출발 주소별로 창을 판정하므로 originator만 뜻이 있다.
    if config["roles"] != [ORIGINATOR]:
        raise ValueError(f"대상 역할은 originator만 지원한다: {config['roles']}")
    label = config["label"]
    if not isinstance(label, str) or not label or label in RESERVED_LABELS:
        raise ValueError(f"쓸 수 없는 라벨: {label!r}")
    limit = config["max_connections"]
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError(f"max_connections는 1 이상의 정수여야 한다: {limit!r}")
    return config


def is_non_host_address(address, networks):
    """호스트가 아닌 주소인지. 255.255.255.255와 멀티캐스트는 참. 내부 주소는 어느 내부 대역에든 속하고
    assets.is_scored_asset이 거짓일 때(= 모든 대역에서 네트워크·브로드캐스트 주소)만 참이다.

    내부 대역이 겹쳐도 자산 규칙과 어긋나지 않는다(예: 10.0.0.0/8과 10.10.0.0/24가 함께 있으면 10.10.0.255는 자산이므로 호스트다).
    내부 대역 밖의 .255는 그 대역의 길이를 모르므로 호스트로 본다. IP가 아닌 값은 ValueError(is_scored_asset과 같다).
    """
    ip = ipaddress.ip_address(address)
    if ip.is_multicast or ip == LIMITED_BROADCAST:
        return True
    # IPv6 주소는 IPv4 대역에 포함되지 않으므로 버전 검사를 따로 하지 않는다.
    return any(ip in net for net in networks) and not is_scored_asset(address, networks)


def count_connections(connections, networks, window_seconds):
    """연결 (출발 주소, 대상 주소, _write_ts)들을 출발 주소 × 창으로 묶어 센다.

    반환: {(자산, 창 시작): [호스트가 아닌 주소행 연결 수, 호스트행 연결 수]}. 연결이 있는 창만 든다.
    """
    counts, cache = {}, {}
    for orig, resp, write_ts in connections:
        key = (orig, time_windows.window_start(write_ts, window_seconds))
        if resp not in cache:
            cache[resp] = is_non_host_address(resp, networks)
        c = counts.setdefault(key, [0, 0])
        c[0 if cache[resp] else 1] += 1
    return counts


def scan_connections(connections, networks, window_seconds, max_connections):
    """연결을 출발 주소 × 창으로 판정한다.

    반환: (라벨 대상 = 연결이 전부 호스트가 아닌 주소행이고 그 수가 max_connections 이하인 (자산, 창) 집합,
           상한을 넘어 큐에 남기는 = 전부 호스트가 아닌 주소행이지만 수가 상한보다 많은 (자산, 창) 집합,
           연결이 하나라도 있는 (자산, 창) 집합).
    """
    counts = count_connections(connections, networks, window_seconds)
    only = {k: n for k, (n, host) in counts.items() if host == 0}
    return ({k for k, n in only.items() if n <= max_connections},
            {k for k, n in only.items() if n > max_connections}, set(counts))


def non_host_only_windows(connections, networks, window_seconds, max_connections):
    """그 창의 연결이 전부 호스트가 아닌 주소행이고 그 수가 max_connections 이하인 (출발 주소, 창 시작) 집합.

    호스트행 연결이 하나라도 있으면 들지 않는다. 연결이 없는 창은 들지 않는다. 상한을 넘는 창은
    scan_connections의 두 번째 값으로 따로 센다.
    """
    return scan_connections(connections, networks, window_seconds, max_connections)[0]


def new_split(role, split, asset_id, window, windows, label):
    """창 점수 행 하나의 새 split. originator이고 집합에 들고 capture_edge가 아니면 label, 아니면 그대로."""
    if role == ORIGINATOR and split not in KEEP_SPLITS and (asset_id, int(window)) in windows:
        return label
    return split


def label_rows(rows, windows, label):
    """dict 행 목록(asset_id, role, window_start, split)에 라벨을 붙인 새 목록. 원래 행은 바꾸지 않는다."""
    return [{**r, "split": new_split(r["role"], r["split"], r["asset_id"], r["window_start"], windows, label)}
            for r in rows]


def label_scores(scores, windows, label, observed=None):
    """창 점수 표(pandas, 세 모델 행)에 라벨을 붙인 새 표.

    observed: 연결이 하나라도 있는 (자산, 창) 집합. 주면 originator 행의 창이 모두 거기 있는지 확인한다
    (연결 자료가 Gold와 다른 행 집합이면 멈춘다).
    """
    keys = list(zip(scores["asset_id"], scores["window_start"].astype("int64")))
    roles = scores["role"].tolist()
    if observed is not None:
        missing = sorted({k for k, r in zip(keys, roles) if r == ORIGINATOR and k not in observed})
        if missing:
            raise ValueError(f"연결 자료에 없는 originator 창 {len(missing)}개(예: {missing[:3]}). "
                             "연결 자료가 Gold와 같은 입력이 아니다")
    out = scores.copy()
    out["split"] = [new_split(r, s, a, w, windows, label)
                    for r, s, (a, w) in zip(roles, scores["split"].tolist(), keys)]
    return out


# --- worker 연결(입력 묶음 정의의 queue_eligibility 항목) ---
# 항목 예: {"config": "configs/worker/queue-eligibility.v1.json", "assets": "configs/assets.lab.v1.json",
#          "silver_dir": "outputs/live/runs/<캡처>/<리비전>/silver/conn_v1"}. 경로는 프로젝트 루트 기준이다.

def silver_manifest(entry, capture_id, root):
    """연결 자료(Silver)의 캡처 manifest. 이 파일이 있어야 완료된 Silver다(scripts/build_silver_conn.py)."""
    return Path(root) / entry["silver_dir"] / "_manifests" / f"{capture_id}.json"


def fingerprint_record(entry, capture_id, root):
    """작업 입력 지문에 넣을 값: 규칙 설정, 자산 설정(내부 대역), 연결 자료 manifest의 해시.

    Silver manifest에는 Parquet 파일 해시가 들어 있으므로 manifest 해시가 같으면 같은 연결 자료다.
    파일이 없으면 FileNotFoundError(계산이 끊긴 리비전, live_agent.revision_for_job이 건너뛴다).
    """
    root = Path(root)
    return {"config": sha256(root / entry["config"]), "assets": sha256(root / entry["assets"]),
            "connections": sha256(silver_manifest(entry, capture_id, root))}


def read_silver_connections(entry, capture_id, root):
    """Silver에서 캡처 하나의 (출발 주소, 대상 주소, _write_ts) 목록. Gold가 읽는 것과 같은 캡처 폴더다."""
    import pandas as pd

    if not silver_manifest(entry, capture_id, root).exists():
        raise FileNotFoundError(f"완료된 Silver가 아니다(manifest 없음): {silver_manifest(entry, capture_id, root)}")
    conn = pd.read_parquet(Path(root) / entry["silver_dir"] / "conn" / f"capture_id={capture_id}",
                           columns=["orig_h", "resp_h", "write_ts"])
    return list(conn.itertuples(index=False, name=None))


def apply_to_set(scores, cfg, capture_id, root):
    """worker의 채점 결과에 set의 규칙을 적용한다. 반환: (DB에 쓸 표, build_queue에 넘길 표, 요약 또는 None).

    항목이 없으면 두 표 모두 원래 표 그대로다(지금까지와 같은 계산).
    """
    entry = cfg.get("queue_eligibility")
    if entry is None:
        return scores, scores, None
    root = Path(root)
    config = load_config(root / entry["config"])
    networks = load_networks([root / entry["assets"]])
    w = time_windows.load_window_config(time_windows.PROJECT_CONFIG)["window_seconds"]
    windows, over, observed = scan_connections(read_silver_connections(entry, capture_id, root), networks, w,
                                               config["max_connections"])
    labeled = label_scores(scores, windows, config["label"], observed)
    hit = labeled["split"] == config["label"]
    excluded = len(set(zip(labeled.loc[hit, "asset_id"], labeled.loc[hit, "window_start"])))
    # 상한을 넘어 큐에 남긴 창: 라벨이 붙었을 자리(originator, capture_edge 아님)인데 연결 수가 상한보다 많은 창
    over_limit = len({k for k in zip(scores["asset_id"], scores["window_start"].astype("int64"), scores["role"],
                                     scores["split"])
                      if k[2] == ORIGINATOR and k[3] not in KEEP_SPLITS and (k[0], int(k[1])) in over})
    summary = {"config_id": config["config_id"], "label": config["label"], "max_connections": config["max_connections"],
               "excluded_windows": excluded, "over_limit_windows": over_limit}
    return labeled, labeled[~hit], summary
