"""실습망 공격마다 파이프라인이 잡았는지와 걸린 시간을 DB 내보내기에서 계산한다(평가 전용).

입력은 정답 설정(lab-attacks.v1)과 DB 표 다섯 개의 행(CSV를 읽은 dict, 값은 문자열)이다.
- scoring_job: 캡처의 마지막 성공 작업 J_c를 고른다. 모델 점수와 조사 큐는 J_c 기준이다.
- window_score: 단위(자산·역할)의 공격 창과 평소 창 점수를 모델별로 견준다.
- incident, incident_window: 조사 큐 순위와, 알림 시점에 사건이 가졌던 창.
- slack_delivery: 공격 창에서 나온 첫 알림과 걸린 시간. 모든 행이 dry_run 기록 시각이다.
종류마다 1~2회 실행한 정성적 프로브라 비율(재현율)을 내지 않는다. 표준 라이브러리만 쓴다.
"""

from collections import defaultdict
from datetime import datetime, timezone
import statistics

from zeek_ad.lab_truth import (
    attack_start, attack_windows, episode_capture, failed_attempt_windows, utc_epoch,
)

VERDICTS = ("detected", "indistinct", "candidate_only", "missed")  # 앞일수록 좋은 판정
LABELS = {"detected": "잡힘", "indistinct": "구분 안 됨", "candidate_only": "후보만", "missed": "놓침"}
# 이 시각 앞의 알림 행에는 스레드 정보가 없다(docs/data-contract-v2.md "스레드 두 열을 읽는 법").
THREAD_INFO_SINCE = utc_epoch("2026-11-19T06:20:00Z")
FEW_NORMAL_WINDOWS = 5  # 평소 창이 이보다 적으면 "견줄 창 적음"으로 표시만 한다


def parse_db_time(text):
    """'2026-11-22 15:47:20.123456+00'(UTC) → epoch 초."""
    text = text.strip()
    if text.endswith("+00"):
        text = text + ":00"
    return datetime.fromisoformat(text).timestamp()


def parse_incident_id(incident_id):
    """'캡처|자산|역할|첫 창 epoch' → (캡처, 자산, 역할, epoch)."""
    capture, asset, role, first = incident_id.split("|")
    return capture, asset, role, int(first)


def is_true(text):
    """PostgreSQL 불리언 내보내기 값('t'·'true')을 참으로 읽는다. 그 밖('f'·빈 칸)은 거짓."""
    return text.strip().lower() in ("t", "true")


def alert_key(delivery):
    """알림 행 하나를 가리키는 키(job_id, incident_id, created_at)."""
    return (delivery["job"], delivery["incident_id"], delivery["created_at"])


def last_job(jobs, capture_id):
    """캡처에서 status = succeeded인 작업 가운데 job_id가 가장 큰 것. 없으면 None."""
    done = [j for j in jobs if j["capture_id"] == capture_id and j["status"] == "succeeded"]
    return max(done, key=lambda j: int(j["job_id"]), default=None)


def index_export(tables):
    """CSV 행을 계산에 쓰는 색인으로 바꾼다. 시각은 epoch, job_id는 정수가 된다."""
    scores = defaultdict(list)  # (job, 자산, 역할) → 점수 행
    for r in tables["window_score"]:
        scores[(int(r["job_id"]), r["asset_id"], r["role"])].append({
            "model": r["model_name"], "window": int(parse_db_time(r["window_start"])), "split": r["split"],
            "score": float(r["score"]), "candidate": is_true(r["is_candidate"]),
        })
    incidents = defaultdict(list)  # job → 사건 행
    for r in tables["incident"]:
        incidents[int(r["job_id"])].append(r)
    incident_windows = defaultdict(set)  # (job, incident_id) → 그 작업에서 사건이 가진 창
    for r in tables["incident_window"]:
        incident_windows[(int(r["job_id"]), r["incident_id"])].add(int(parse_db_time(r["window_start"])))
    deliveries = []
    for r in tables["slack_delivery"]:
        capture, asset, role, _ = parse_incident_id(r["incident_id"])
        deliveries.append({**r, "job": int(r["job_id"]), "capture": capture, "asset": asset, "role": role,
                           "created": parse_db_time(r["created_at"])})
    deliveries.sort(key=lambda d: d["created"])
    return {
        "jobs": {int(j["job_id"]): j for j in tables["scoring_job"]},
        "scores": scores, "incidents": incidents, "incident_windows": incident_windows,
        "deliveries": deliveries,
    }


def channel_visible(delivery):
    """채널에 보였는지. 스레드 정보가 없던 때의 기록이면 None."""
    if delivery["created"] < THREAD_INFO_SINCE:
        return None
    return delivery["thread_parent"].strip() == "" or is_true(delivery["reply_broadcast"])


def model_stats(rows, attack, not_normal):
    """한 단위·한 모델의 공격 창 대 평소 창 값.

    attack: 이 에피소드의 공격 창 W_e. not_normal: 평소 창이 될 수 없는 창
    (이 단위의 모든 에피소드 공격 창 A_u와 실패한 시도의 창). 평소 창은 split = live이고 not_normal에 없는 창이다.
    """
    hits = [r for r in rows if r["window"] in attack]
    normal = [r for r in rows if r["split"] == "live" and r["window"] not in not_normal]
    normal_scores = [r["score"] for r in normal]
    return {
        "attack_scored": len(hits),
        "attack_unscored": len(attack) - len(hits),
        "attack_candidates": sum(r["candidate"] for r in hits),
        "attack_max": max((r["score"] for r in hits), default=None),
        "attack_capture_edge": sorted(r["window"] for r in hits if r["split"] == "capture_edge"),
        "normal_windows": len(normal),
        "normal_candidates": sum(r["candidate"] for r in normal),
        "normal_max": max(normal_scores, default=None),
        "normal_median": statistics.median(normal_scores) if normal_scores else None,
    }


def is_distinct(stats):
    """평소와 구분되는 모델: 공격 창에서 후보였고, 평소 창이 있고, 공격 최고 > 평소 최고(같으면 아님)."""
    return (stats["attack_candidates"] > 0 and stats["normal_windows"] > 0
            and stats["attack_max"] > stats["normal_max"])


def alerts_from_attack(index, unit_key, attack, t0):
    """공격 창에서 나온 알림 행(이른 순). 알림 작업에서 사건이 가졌던 창이 W_e와 겹쳐야 한다.

    뒤 작업에서 사건이 자라 공격 창을 덮게 된 것은 세지 않는다. created_at == t0는 센다.
    """
    found = []
    for d in index["deliveries"]:
        if d["report_version"].startswith("status:") or (d["capture"], d["asset"], d["role"]) != unit_key:
            continue
        if d["created"] < t0:
            continue
        overlap = index["incident_windows"].get((d["job"], d["incident_id"]), set()) & attack
        if overlap:
            found.append((d, min(overlap)))
    return found


def evaluate_unit(index, unit, capture, job_id, attack, attack_union, failed, t0, window_seconds):
    """에피소드 하나의 당사자 단위 하나를 평가한다.

    attack_union: 이 단위의 A_u. failed: 이 단위의 실패한 시도 창(평소 창에서 뺀다).
    """
    unit_key = (capture, unit["asset"], unit["role"])
    rows = index["scores"].get((job_id, unit["asset"], unit["role"]), [])
    not_normal = attack_union | failed
    by_model = defaultdict(list)
    for r in rows:
        by_model[r["model"]].append(r)
    models = {m: model_stats(rs, attack, not_normal) for m, rs in sorted(by_model.items())}
    for s in models.values():
        s["distinct"] = is_distinct(s)
    # 단위의 평소 창은 모델을 합쳐 센다. 하나도 없으면 견줄 창이 없어 구분 여부를 정하지 않는다.
    live = {r["window"] for r in rows if r["split"] == "live"}
    normal_windows = live - not_normal
    failed_excluded = (live & failed) - attack_union
    distinct_models = [m for m, s in models.items() if s["distinct"]] if normal_windows else None

    queue = []
    job_incidents = index["incidents"].get(job_id, [])
    for inc in job_incidents:
        if (inc["asset_id"], inc["role"]) != (unit["asset"], unit["role"]):
            continue
        if parse_incident_id(inc["incident_id"])[0] != capture:
            continue
        covered = index["incident_windows"].get((job_id, inc["incident_id"]), set()) & attack
        if covered:
            queue.append({
                "incident_id": inc["incident_id"], "queue_rank": int(inc["queue_rank"]),
                "incidents_in_job": len(job_incidents), "first_start": inc["first_start"],
                "last_end": inc["last_end"], "picked_by": inc["picked_by"],
                "also_flagged_by": inc["also_flagged_by"], "attack_windows_covered": len(covered),
            })
    queue.sort(key=lambda q: q["queue_rank"])

    alerts = alerts_from_attack(index, unit_key, attack, t0)
    attack_keys = {alert_key(d) for d, _ in alerts}
    first_alert = None
    if alerts:
        d, first_window = alerts[0]
        first_alert = {
            "created_at": d["created_at"], "created_epoch": d["created"], "job_id": d["job"],
            "bundle_id": index["jobs"].get(d["job"], {}).get("bundle_id"),
            "report_version": d["report_version"], "incident_id": d["incident_id"], "mode": d["mode"],
            "latency_s": d["created"] - t0,
            "latency_after_window_close_s": d["created"] - (first_window + window_seconds),
            "channel_visible": channel_visible(d),
            "key": list(alert_key(d)), "shared_with_episodes": [],
        }

    # 흡수된 사건: J_c에서 공격 창과 겹치는 사건이 알림 행은 있는데, 그 가운데 공격 창 알림이 하나도 없다.
    # 단위에 다른 사건의 공격 창 알림이 있어도 사건마다 본다(그때는 일부 흡수).
    absorbed = []
    for q in queue:
        rows_for = [d for d in index["deliveries"] if d["incident_id"] == q["incident_id"]
                    and not d["report_version"].startswith("status:")]
        if rows_for and not any(alert_key(d) in attack_keys for d in rows_for):
            absorbed.append({
                "incident_id": q["incident_id"], "first_alert_at": rows_for[0]["created_at"],
                "first_alert_job_id": rows_for[0]["job"],
                "attack_windows_covered": q["attack_windows_covered"],
                "alert_keys": [list(alert_key(d)) for d in rows_for], "absorbed_into_episodes": [],
            })
    return {
        "asset": unit["asset"], "role": unit["role"],
        "normal_window_count": len(normal_windows),
        "failed_attempt_windows_excluded": len(failed_excluded),
        "few_normal_windows": 0 < len(normal_windows) < FEW_NORMAL_WINDOWS,
        "models": models, "distinct_models": distinct_models,
        "queue": queue, "attack_alert_count": len(alerts),
        "attack_alert_keys": sorted(list(k) for k in attack_keys),
        "attack_alert_bundles": sorted({index["jobs"].get(d["job"], {}).get("bundle_id") or "?"
                                        for d, _ in alerts}),
        "first_alert": first_alert, "absorbed": absorbed,
        "partially_absorbed": bool(absorbed and alerts),
    }


def unit_attack_union(episodes, capture, unit):
    """캡처 c에서 단위 u가 당사자인 모든 에피소드의 공격 창 합집합 A_u."""
    union = set()
    for ep in episodes:
        if episode_capture(ep) == capture and any(
                (u["asset"], u["role"]) == (unit["asset"], unit["role"]) for u in ep["expected_units"]):
            union.update(attack_windows(ep))
    return union


def unit_name(u):
    return f"{u['asset']} {u['role']}"


def evaluate_episode(index, episode, episodes, job_id, window_seconds, failed_by_unit=None):
    """에피소드 하나의 단위별 값과 판정(위에서부터 처음 맞는 것)."""
    failed_by_unit = failed_by_unit or {}
    capture = episode_capture(episode)
    attack = set(attack_windows(episode))
    t0 = attack_start(episode)
    units = [evaluate_unit(index, u, capture, job_id, attack, unit_attack_union(episodes, capture, u),
                           failed_by_unit.get((capture, u["asset"], u["role"]), set()), t0, window_seconds)
             for u in episode["expected_units"]]
    alerted = [u for u in units if u["first_alert"]]
    deciding = [u for u in alerted if u["distinct_models"]]
    if deciding:
        verdict = "detected"
    elif alerted:
        verdict, deciding = "indistinct", alerted
    elif any(s["attack_candidates"] > 0 for u in units for s in u["models"].values()):
        verdict, deciding = "candidate_only", []
    else:
        verdict, deciding = "missed", []
    first = min(deciding, key=lambda u: u["first_alert"]["created_epoch"], default=None)
    # 표에 쓰는 구분된 모델은 판정을 만든 단위(잡힘일 때)의 것만이다. 나머지 단위의 것은 따로 남긴다.
    deciding_distinct = sorted({m for u in deciding for m in (u["distinct_models"] or [])}) \
        if verdict == "detected" else []
    deciding_ids = {id(u) for u in deciding} if verdict == "detected" else set()
    other_distinct = [{"unit": unit_name(u), "models": u["distinct_models"]} for u in units
                      if u["distinct_models"] and id(u) not in deciding_ids]
    return {
        "episode_id": episode["episode_id"], "scenario": episode["scenario"], "run": episode["run"],
        "capture_id": capture, "job_id": job_id, "t0_utc": episode["observed"]["first_ts_utc"],
        "attack_windows": sorted(attack), "verdict": verdict,
        "deciding_units": [unit_name(u) for u in deciding],
        "first_alert": ({"unit": unit_name(first), **first["first_alert"]} if first else None),
        "deciding_distinct_models": deciding_distinct,
        "non_deciding_distinct": other_distinct,
        "all_distinct_models": sorted({m for u in units for m in (u["distinct_models"] or [])}),
        "has_distinct_model": any(u["distinct_models"] for u in units),
        "shares_alert_with": [],
        "units": units,
    }


def link_shared_alerts(results):
    """에피소드 사이의 알림 공유와, 다른 공격의 알림에 흡수된 사건을 표시한다."""
    first_users = defaultdict(set)  # 알림 키 → 그 알림을 단위의 첫 알림으로 쓴 에피소드
    attack_users = defaultdict(set)  # 알림 키 → 그 알림을 공격 창 알림으로 가진 에피소드
    for ep in results:
        for u in ep["units"]:
            if u["first_alert"]:
                first_users[tuple(u["first_alert"]["key"])].add(ep["episode_id"])
            for k in u["attack_alert_keys"]:
                attack_users[tuple(k)].add(ep["episode_id"])
    for ep in results:
        shared = set()
        for u in ep["units"]:
            if u["first_alert"]:
                others = first_users[tuple(u["first_alert"]["key"])] - {ep["episode_id"]}
                u["first_alert"]["shared_with_episodes"] = sorted(others)
                shared |= others
            for b in u["absorbed"]:
                into = set().union(*(attack_users[tuple(k)] for k in b["alert_keys"])) - {ep["episode_id"]}
                b["absorbed_into_episodes"] = sorted(into)
        ep["shares_alert_with"] = sorted(shared)
        if ep["first_alert"]:
            ep["first_alert"]["shared_with_episodes"] = sorted(
                first_users[tuple(ep["first_alert"]["key"])] - {ep["episode_id"]})


def summarize_scenarios(results):
    """종류별로 실행마다의 판정을 모은다. 대표 판정은 실행 가운데 가장 좋은 것(하나라도 잡히면 잡힘)."""
    by_scenario = defaultdict(list)
    for r in results:
        by_scenario[r["scenario"]].append(r)
    summary = []
    for scenario, runs in by_scenario.items():
        runs = sorted(runs, key=lambda r: r["run"])
        summary.append({
            "scenario": scenario, "runs": len(runs),
            "best_verdict": min((r["verdict"] for r in runs), key=VERDICTS.index),
            "per_run": [{
                "run": r["run"], "episode_id": r["episode_id"], "verdict": r["verdict"],
                "latency_s": r["first_alert"]["latency_s"] if r["first_alert"] else None,
                "deciding_distinct_models": r["deciding_distinct_models"],
            } for r in runs],
        })
    return summary


def evaluate(config, tables):
    """전체 계산. 캡처마다 마지막 작업을 고르고 에피소드마다 판정한다."""
    index = index_export(tables)
    episodes = config["episodes"]
    failed = failed_attempt_windows(config)
    captures = {}
    for capture in sorted({episode_capture(ep) for ep in episodes}):
        job = last_job(tables["scoring_job"], capture)
        if job is None:
            raise ValueError(f"{capture}: 성공한 채점 작업이 없다")
        job_id = int(job["job_id"])
        captures[capture] = {"last_job_id": job_id, "bundle_id": job["bundle_id"],
                             "finished_at": job["finished_at"],
                             "incidents_in_job": len(index["incidents"].get(job_id, []))}
    results = [evaluate_episode(index, ep, episodes, captures[episode_capture(ep)]["last_job_id"],
                                config["window_seconds"], failed) for ep in episodes]
    link_shared_alerts(results)
    for capture, info in captures.items():
        # 공격 창 알림을 기록한 작업의 묶음. 마지막 작업의 묶음과 다를 수 있다.
        info["alert_bundles"] = sorted({b for ep in results if ep["capture_id"] == capture
                                        for u in ep["units"] for b in u["attack_alert_bundles"]})
    scenarios = summarize_scenarios(results)
    totals = {v: sum(s["best_verdict"] == v for s in scenarios) for v in VERDICTS}
    return {"captures": captures, "episodes": results, "scenarios": scenarios, "scenario_totals": totals}


# ---- detection.md 렌더링 ----

def _hm(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%H:%M")


def _stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%m-%d %H:%M:%S")


def _minutes(seconds):
    return "—" if seconds is None else f"{seconds / 60:.1f}"


def _num(x):
    return "—" if x is None else f"{x:.2f}"


def _model_cell(s):
    cell = (f"공격 {s['attack_candidates']}/{s['attack_scored']}, {_num(s['attack_max'])} 대 "
            f"평소 {s['normal_candidates']}/{s['normal_windows']}, {_num(s['normal_max'])}")
    extra = []
    if s["distinct"]:
        extra.append("구분")
    if s["attack_unscored"]:
        extra.append(f"점수 없는 공격 창 {s['attack_unscored']}")
    if s["attack_capture_edge"]:
        extra.append(f"capture_edge {','.join(_hm(w) for w in s['attack_capture_edge'])}")
    return cell + (f" ({'; '.join(extra)})" if extra else "")


def _channel_text(alert):
    if alert is None:
        return "—"
    return {None: "정보 없음", True: "보임", False: "스레드 안"}[alert["channel_visible"]]


def _absorbed_label(u):
    """흡수 표시. 단위에 공격 창 알림도 있으면 일부 흡수, 다른 공격의 알림이면 그 에피소드를 붙인다."""
    if not u["absorbed"]:
        return None
    label = "일부 흡수" if u["partially_absorbed"] else "흡수됨"
    into = sorted({e for b in u["absorbed"] for e in b["absorbed_into_episodes"]})
    return label + (f"(다른 공격 {', '.join(into)}의 알림)" if into else "")


def _unit_notes(u):
    notes = []
    if u["distinct_models"] is None:
        notes.append("견줄 창 없음")
    elif u["few_normal_windows"]:
        notes.append(f"견줄 창 적음({u['normal_window_count']})")
    if u["failed_attempt_windows_excluded"]:
        notes.append(f"실패한 시도 창 {u['failed_attempt_windows_excluded']}개 뺌")
    label = _absorbed_label(u)
    if label:
        notes.append(label)
    return notes


def _latency_cell(r):
    if r["verdict"] == "detected":
        return _minutes(r["latency_s"])
    if r["verdict"] == "indistinct":
        return f"(알림 {_minutes(r['latency_s'])}분, 구분 안 됨)"
    return "—"


def render_markdown(result, config, export_label):
    """detection.md 본문. 물결표는 GitHub 취소선이 되지 않게 이스케이프한다."""
    models = sorted({m for ep in result["episodes"] for u in ep["units"] for m in u["models"]})
    totals = result["scenario_totals"]
    lines = [
        "# 실습망 공격 탐지 여부·걸린 시간",
        "",
        f"- 정답 설정: `{config['config_id']}` (에피소드 {len(config['episodes'])}개, 종류 {len(result['scenarios'])}개)",
        f"- DB 내보내기: `{export_label}`",
        "- 캡처별 마지막 작업(모델 점수·조사 큐의 기준)과 알림을 기록한 작업의 묶음: " + "; ".join(
            f"`{c}` 마지막 job {v['last_job_id']} (`{v['bundle_id']}`, 사건 {v['incidents_in_job']}개), "
            f"공격 창 알림은 {', '.join(f'`{b}`' for b in v['alert_bundles']) or '없음'} 작업에서 기록"
            for c, v in result["captures"].items()),
        "- 판정(위에서부터): 잡힘 = 공격 창에서 나온 알림이 있고 평소와 구분되는 모델이 있는 단위가 있음, "
        "구분 안 됨 = 알림은 있으나 그런 단위가 없음, 후보만 = 알림 없이 공격 창 후보만, 놓침 = 공격 창 후보 없음.",
        "- 평소와 구분 = 공격 창에서 후보였고 공격 창 최고 점수 > 평소 창 최고 점수. 평소 창은 그 단위의 공격 창 밖 live 창이고 "
        "연결 확인과 정상 배경이 든다(실패한 시도의 창은 뺐다). "
        f"평소 창이 {FEW_NORMAL_WINDOWS}개 미만인 단위의 \"구분\"은 근거가 얇다.",
        "- 걸린 시간 = 첫 알림 기록 시각 − 첫 공격 연결 시작. 표 1에는 잡힘일 때만 숫자로 쓰고, 구분 안 됨은 괄호 안에 참고로 쓴다. "
        "모든 알림은 dry_run 기록 시각이다.",
        f"- 종류별 대표 판정: 잡힘 {totals['detected']}종, 구분 안 됨 {totals['indistinct']}종, "
        f"후보만 {totals['candidate_only']}종, 놓침 {totals['missed']}종. 종류마다 1~2회의 정성적 프로브라 비율을 내지 않는다.",
        "",
        "## 표 1. 종류별",
        "",
        "구분된 모델은 판정을 만든 단위(알림 있고 구분되는 단위)의 것만 쓴다. 비고의 알림 공유는 같은 알림 행이 다른 에피소드의 "
        "첫 알림이기도 하다는 뜻이고, 흡수됨은 공격 창과 겹치는 사건이 공격 창 밖의 알림만 가졌다는 뜻이다.",
        "",
        "| 종류 | 실행 수 | 판정(실행별) | 걸린 시간(분) | 구분된 모델 | 비고 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    by_id = {ep["episode_id"]: ep for ep in result["episodes"]}
    for s in result["scenarios"]:
        verdicts, latencies, distinct, notes = [], [], [], []
        for r in s["per_run"]:
            ep = by_id[r["episode_id"]]
            verdicts.append(f"{r['run']}: {LABELS[r['verdict']]}")
            latencies.append(f"{r['run']}: {_latency_cell(r)}")
            distinct.append(f"{r['run']}: {', '.join(r['deciding_distinct_models']) or '—'}")
            run_notes = []
            for u in ep["units"]:
                if u["distinct_models"] is None:
                    run_notes.append(f"견줄 창 없음 {unit_name(u)}")
                elif u["few_normal_windows"]:
                    run_notes.append(f"견줄 창 적음({u['normal_window_count']}) {unit_name(u)}")
                label = _absorbed_label(u)
                if label:
                    run_notes.append(f"{label} {unit_name(u)}")
            for d in ep["non_deciding_distinct"]:
                run_notes.append(f"알림 없는 단위에서 구분: {', '.join(d['models'])}({d['unit']})")
            if ep["shares_alert_with"]:
                run_notes.append(f"알림 공유: {', '.join(ep['shares_alert_with'])}")
            if run_notes:
                notes.append(f"{r['run']}: " + ", ".join(run_notes))
        lines.append(f"| {s['scenario']} | {s['runs']} | {' / '.join(verdicts)} | {' / '.join(latencies)} | "
                     f"{' / '.join(distinct)} | {' / '.join(notes) or '—'} |")

    lines += [
        "",
        "## 표 2. 에피소드 × 단위",
        "",
        "모델 칸: `공격 후보/공격 창, 최고 대 평소 후보/평소 창, 최고`. 큐 순위는 마지막 작업(J_c)에서 공격 창과 겹치는 사건의 "
        "`순위/전체 사건 수`라 알림을 낸 사건과 다를 수 있다. "
        f"평소 창이 {FEW_NORMAL_WINDOWS}개 미만이면 견줄 창 적음으로 표시한다(판정은 바꾸지 않는다).",
        "",
        "| 에피소드 | 단위 | " + " | ".join(models) + " | 큐 순위 | 첫 알림(시각, 걸린 분) | 채널 |",
        "| --- | --- | " + "--- | " * len(models) + "--- | --- | --- |",
    ]
    for ep in result["episodes"]:
        windows = ",".join(_hm(w) for w in ep["attack_windows"])
        for u in ep["units"]:
            notes = _unit_notes(u)
            unit = unit_name(u) + (f" ({', '.join(notes)})" if notes else "")
            cells = [_model_cell(u["models"][m]) if m in u["models"] else "점수 없음" for m in models]
            queue = ", ".join(f"{q['queue_rank']}/{q['incidents_in_job']}" for q in u["queue"]) or "—"
            parts = []
            a = u["first_alert"]
            if a:
                text = (f"{_stamp(a['created_epoch'])} ({_minutes(a['latency_s'])}분, 창 닫힌 뒤 "
                        f"{_minutes(a['latency_after_window_close_s'])}분, job {a['job_id']} `{a['bundle_id']}`, "
                        f"{a['report_version']})")
                if a["shared_with_episodes"]:
                    text += f", 알림 공유: {', '.join(a['shared_with_episodes'])}"
                parts.append(text)
            for b in u["absorbed"]:
                text = (f"흡수: {b['incident_id'].rsplit('|', 1)[-1]} 사건(공격 창 {b['attack_windows_covered']}개 덮음, "
                        f"{b['first_alert_at'][5:19]} 알림")
                if b["absorbed_into_episodes"]:
                    text += f", {', '.join(b['absorbed_into_episodes'])}의 알림"
                parts.append(text + ")")
            lines.append(f"| {ep['episode_id']} {ep['scenario']} {ep['run']} ({windows}, {LABELS[ep['verdict']]}) | "
                         f"{unit} | " + " | ".join(cells) + f" | {queue} | {'; '.join(parts) or '—'} | "
                         f"{_channel_text(a)} |")
    return "\n".join(lines).replace("~", "\\~") + "\n"
