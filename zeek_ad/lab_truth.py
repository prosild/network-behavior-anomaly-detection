"""실습망 공격 정답 설정(lab-attacks.v1)을 읽고 Zeek conn 행에 규칙을 적용한다(평가 전용).

규칙의 뜻은 설정의 rule_semantics를 따른다. 연결은 수집 파일 폴더 + uid로 구별한다.
5분 수집 파일마다 Zeek을 따로 돌려 uid가 파일 사이에서 겹치기 때문이다.
창은 파이프라인과 같이 _write_ts를 window_seconds로 내림해 정한다(설정의 window_basis).
표준 라이브러리만 쓴다.
"""

from collections import Counter
from datetime import datetime, timezone
import json
import math
from pathlib import Path

from zeek_ad.windows import window_start

PROJECT_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "ground-truth" / "lab-attacks.v1.json"
STATUSES = ("confirmed", "uncertain", "unsupported")
ROLES = ("originator", "responder")


def load_config(path=PROJECT_CONFIG):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def utc_epoch(text):
    """'2026-11-22T14:06:00Z' 같은 UTC 문자열을 epoch 초로 바꾼다."""
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def utc_text(epoch):
    """epoch 초를 초 아래를 버린 UTC 문자열로 바꾼다."""
    return datetime.fromtimestamp(math.floor(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def capture_date(capture_id):
    """'lab-20261122' → '2026-11-22'. 캡처 이름 끝 8자리가 UTC 날짜다."""
    digits = capture_id.rsplit("-", 1)[-1]
    if len(digits) != 8 or not digits.isdigit():
        raise ValueError(f"캡처 이름에서 날짜를 읽을 수 없다: {capture_id}")
    return f"{digits[:4]}-{digits[4:6]}-{digits[6:]}"


def conn_record(capture_id, folder, raw):
    """conn.log JSON 한 줄(dict)을 규칙 적용에 쓰는 모양으로 줄인다."""
    return {
        "capture_id": capture_id,
        "folder": folder,
        "uid": raw["uid"],
        "ts": float(raw["ts"]),
        "write_ts": float(raw["_write_ts"]),
        "orig_h": raw["id.orig_h"],
        "resp_h": raw["id.resp_h"],
        "resp_p": raw.get("id.resp_p"),
        "proto": raw.get("proto"),
    }


def connection_key(record):
    # uid만으로는 파일 사이에서 겹친다. 캡처·폴더를 함께 쓴다.
    return (record["capture_id"], record["folder"], record["uid"])


def read_capture_conn(zeek_root, capture_id):
    """outputs/live/zeek/<capture_id>/<폴더>/conn.log를 모두 읽어 conn_record 목록을 돌려준다."""
    records = []
    for path in sorted(Path(zeek_root, capture_id).glob("*/conn.log")):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    records.append(conn_record(capture_id, path.parent.name, json.loads(line)))
    return records


def rule_matches(rule, record):
    """규칙 하나의 모든 조건(AND)을 만족하는지. ts는 [시작, 끝) 반열린 구간이다."""
    if record["capture_id"] != rule["capture_id"]:
        return False
    if record["orig_h"] not in rule["orig_h"] or record["resp_h"] not in rule["resp_h"]:
        return False
    if not utc_epoch(rule["ts_start_utc"]) <= record["ts"] < utc_epoch(rule["ts_end_utc"]):
        return False
    if "resp_p" in rule and record["resp_p"] not in rule["resp_p"]:
        return False
    if "proto" in rule and record["proto"] != rule["proto"]:
        return False
    return True


def episode_connections(episode, records):
    """에피소드 규칙들의 합집합. 같은 연결이 규칙 둘에 걸려도 한 번만 남긴다."""
    chosen = {}
    for record in records:
        if any(rule_matches(rule, record) for rule in episode["rules"]):
            chosen.setdefault(connection_key(record), record)
    return list(chosen.values())


def overlapping_connections(connections_by_episode):
    """{episode_id: [연결]} → 둘 이상의 에피소드에 들어간 연결의 {연결 키: [episode_id]}.

    한 연결이 두 에피소드에 들어가면 조건이 겹친 것이라 대응이 모호해진다.
    """
    owners = {}
    for episode_id, connections in connections_by_episode.items():
        for record in connections:
            owners.setdefault(connection_key(record), []).append(episode_id)
    return {key: ids for key, ids in sorted(owners.items()) if len(ids) > 1}


def failed_attempt_windows(config):
    """other_activity의 실패한 시도(failed_attempt) 창. (캡처, 자산, 역할) → 창 epoch 집합.

    이 창은 공격 창이 아니면서 평소 창도 아니다(평소 창에서 뺀다).
    """
    found = {}
    for item in config.get("other_activity", []):
        if item["kind"] != "failed_attempt":
            continue
        date = capture_date(item["capture_id"])
        starts = {int(utc_epoch(f"{date}T{hhmm}:00Z")) for hhmm in item["windows_utc"]}
        for unit in item["units"]:
            found.setdefault((item["capture_id"], unit["asset"], unit["role"]), set()).update(starts)
    return found


def episode_capture(episode):
    """에피소드의 캡처. 규칙이 여러 캡처에 걸치면 창 이름(HH:MM)이 모호해지므로 멈춘다."""
    captures = {rule["capture_id"] for rule in episode["rules"]}
    if len(captures) != 1:
        raise ValueError(f"{episode['episode_id']}: 캡처가 하나가 아니다: {sorted(captures)}")
    return captures.pop()


def observe(connections, capture_id, window_seconds):
    """연결 목록의 관측값. 설정의 observed와 같은 모양이다."""
    if not connections:
        return {"connections": 0, "first_ts_utc": None, "last_ts_utc": None,
                "windows_utc": [], "connections_per_window": {}}
    date = capture_date(capture_id)
    per_window = Counter()
    for record in connections:
        start = window_start(record["write_ts"], window_seconds)
        stamp = datetime.fromtimestamp(start, timezone.utc)
        # 창 이름은 캡처 날짜 위의 HH:MM이다. 날짜를 넘는 창은 이름으로 나타낼 수 없다.
        if stamp.strftime("%Y-%m-%d") != date:
            raise ValueError(f"캡처 날짜({date}) 밖의 창: {stamp.isoformat()}")
        per_window[stamp.strftime("%H:%M")] += 1
    names = sorted(per_window)
    return {
        "connections": len(connections),
        "first_ts_utc": utc_text(min(r["ts"] for r in connections)),
        "last_ts_utc": utc_text(max(r["ts"] for r in connections)),
        "windows_utc": names,
        "connections_per_window": {name: per_window[name] for name in names},
    }


def attack_windows(episode):
    """에피소드의 공격 창 W_e를 epoch 초(정수) 목록으로. observed.windows_utc + 캡처 날짜."""
    date = capture_date(episode_capture(episode))
    return sorted(int(utc_epoch(f"{date}T{hhmm}:00Z")) for hhmm in episode["observed"]["windows_utc"])


def attack_start(episode):
    """걸린 시간의 시작점 t0(설정의 timing_basis)."""
    return utc_epoch(episode["observed"]["first_ts_utc"])


def config_problems(config):
    """정답 설정의 형식 검사. 문제를 문장 목록으로 돌려준다(비면 통과)."""
    problems = []
    ids = Counter(ep["episode_id"] for ep in config["episodes"])
    problems += [f"episode_id 중복: {i}" for i, n in ids.items() if n > 1]
    w = config["window_seconds"]
    for ep in config["episodes"]:
        eid, obs = ep["episode_id"], ep["observed"]
        if ep["status"] not in STATUSES:
            problems.append(f"{eid}: 알 수 없는 status {ep['status']}")
        if not ep.get("rules"):
            problems.append(f"{eid}: 규칙이 없다")
        for unit in ep["expected_units"]:
            if unit["role"] not in ROLES:
                problems.append(f"{eid}: 알 수 없는 role {unit['role']}")
        names = obs["windows_utc"]
        if names != sorted(names) or len(set(names)) != len(names):
            problems.append(f"{eid}: windows_utc가 정렬·유일하지 않다")
        if list(obs["connections_per_window"]) != names:
            problems.append(f"{eid}: connections_per_window의 창이 windows_utc와 다르다")
        if sum(obs["connections_per_window"].values()) != obs["connections"]:
            problems.append(f"{eid}: 창별 연결 수의 합이 connections와 다르다")
        if utc_epoch(obs["first_ts_utc"]) > utc_epoch(obs["last_ts_utc"]):
            problems.append(f"{eid}: first_ts_utc가 last_ts_utc보다 늦다")
        for hhmm in names:
            h, m = hhmm.split(":")
            if (int(h) * 3600 + int(m) * 60) % w:
                problems.append(f"{eid}: 창 {hhmm}이 {w}초 경계가 아니다")
    # 실패한 시도는 평소 창에서 뺄 단위와 창이 있어야 한다.
    for i, item in enumerate(config.get("other_activity", [])):
        if item.get("kind") != "failed_attempt":
            continue
        missing = [k for k in ("capture_id", "units", "windows_utc") if not item.get(k)]
        if missing:
            problems.append(f"other_activity[{i}] failed_attempt: {', '.join(missing)}가 없다")
            continue
        for unit in item["units"]:
            if unit.get("role") not in ROLES or not unit.get("asset"):
                problems.append(f"other_activity[{i}] failed_attempt: 단위 형식이 틀렸다 {unit}")
    return problems
