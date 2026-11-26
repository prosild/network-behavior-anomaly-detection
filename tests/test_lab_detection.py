from datetime import datetime, timezone
import unittest

import re

from zeek_ad.lab_detection import (
    THREAD_INFO_SINCE, channel_visible, evaluate, is_distinct, last_job, model_stats, render_markdown,
    summarize_scenarios,
)


# 규칙 확인용 가짜 예제다. 실제 실습망 기록이 아니다.
CAP = "lab-20300101"
A = {"asset": "10.0.0.50", "role": "originator"}
B = {"asset": "10.0.0.20", "role": "responder"}
M1, M2 = "model_a", "model_b"


def utc(h, m, s=0.0):
    return datetime(2030, 1, 1, h, m, tzinfo=timezone.utc).timestamp() + s


def db(epoch):
    """DB 내보내기 시각 형식."""
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f") + "+00"


def episode(eid, windows, units=(A, B), first="10:06:16", scenario="scan", run=1, capture=CAP):
    return {
        "episode_id": eid, "scenario": scenario, "run": run, "expected_units": list(units),
        "rules": [{"capture_id": capture}],
        "observed": {"first_ts_utc": f"2030-01-01T{first}Z", "windows_utc": list(windows)},
    }


def iid(unit, hhmm):
    h, m = hhmm.split(":")
    return f"{CAP}|{unit['asset']}|{unit['role']}|{int(utc(int(h), int(m)))}"


class Tables:
    """가짜 DB 내보내기. CSV처럼 값은 모두 문자열이다."""

    def __init__(self, last=10):
        self.t = {"scoring_job": [], "window_score": [], "incident": [], "incident_window": [],
                  "slack_delivery": []}
        self.job(last)

    def job(self, job_id, status="succeeded", capture=CAP):
        self.t["scoring_job"].append({"job_id": str(job_id), "capture_id": capture, "bundle_id": f"b/{job_id}",
                                      "status": status, "started_at": "", "finished_at": ""})

    def score(self, unit, hhmm, score, cand, model=M1, job=10, split="live"):
        h, m = hhmm.split(":")
        self.t["window_score"].append({
            "job_id": str(job), "model_name": model, "asset_id": unit["asset"], "role": unit["role"],
            "window_start": db(utc(int(h), int(m))), "split": split, "score": str(score),
            "is_candidate": "t" if cand else "f"})

    def normal(self, unit, n=5, score=1.0, model=M1, job=10):
        for i in range(n):
            self.score(unit, f"09:{i * 5:02d}", score, False, model, job)

    def incident(self, unit, first, windows, job, rank=1, capture=CAP):
        incident_id = iid(unit, first).replace(CAP, capture)
        self.t["incident"].append({"job_id": str(job), "incident_id": incident_id, "queue_rank": str(rank),
                                   "asset_id": unit["asset"], "role": unit["role"], "first_start": "",
                                   "last_end": "", "picked_by": M1, "also_flagged_by": "{}"})
        for w in windows:
            h, m = w.split(":")
            self.t["incident_window"].append({"job_id": str(job), "incident_id": incident_id,
                                              "window_start": db(utc(int(h), int(m)))})
        return incident_id

    def slack(self, incident_id, job, created, version="template.v1", parent="", broadcast="f"):
        self.t["slack_delivery"].append({
            "job_id": str(job), "incident_id": incident_id, "report_version": version, "mode": "dry_run",
            "status": "recorded", "created_at": db(created), "thread_parent": parent,
            "reply_broadcast": broadcast})


def run(tables, *episodes, other_activity=()):
    return evaluate({"window_seconds": 300, "episodes": list(episodes), "other_activity": list(other_activity)},
                    tables.t)


def unit_of(result, unit, eid="ep-1"):
    ep = next(e for e in result["episodes"] if e["episode_id"] == eid)
    return next(u for u in ep["units"] if (u["asset"], u["role"]) == (unit["asset"], unit["role"]))


class LastJobTest(unittest.TestCase):
    def test_failed_job_with_larger_id_is_skipped(self):
        jobs = [{"job_id": "9", "capture_id": CAP, "status": "succeeded"},
                {"job_id": "12", "capture_id": CAP, "status": "failed"},
                {"job_id": "10", "capture_id": CAP, "status": "succeeded"},
                {"job_id": "99", "capture_id": "lab-20300102", "status": "succeeded"}]
        self.assertEqual(last_job(jobs, CAP)["job_id"], "10")  # 문자열 순서가 아니라 숫자 순서
        self.assertIsNone(last_job(jobs, "lab-20300103"))


def scored(rows):
    return [{"window": int(utc(int(w[:2]), int(w[3:]))), "split": split, "score": s, "candidate": c}
            for w, s, c, split in rows]


ATTACK = {int(utc(10, 5)), int(utc(10, 10))}


class DistinctTest(unittest.TestCase):
    def test_attack_max_above_normal_max(self):
        s = model_stats(scored([("10:05", 5.0, True, "live"), ("10:10", 3.0, False, "live"),
                                ("09:00", 4.0, True, "live"), ("09:05", 1.0, False, "live")]), ATTACK, ATTACK)
        self.assertEqual((s["attack_candidates"], s["attack_scored"], s["attack_max"]), (1, 2, 5.0))
        self.assertEqual((s["normal_candidates"], s["normal_windows"], s["normal_max"]), (1, 2, 4.0))
        self.assertEqual(s["normal_median"], 2.5)
        self.assertTrue(is_distinct(s))

    def test_equal_max_is_not_distinct(self):
        s = model_stats(scored([("10:05", 4.0, True, "live"), ("09:00", 4.0, False, "live")]), ATTACK, ATTACK)
        self.assertFalse(is_distinct(s))

    def test_high_score_without_candidate_is_not_distinct(self):
        s = model_stats(scored([("10:05", 9.0, False, "live"), ("09:00", 1.0, False, "live")]), ATTACK, ATTACK)
        self.assertFalse(is_distinct(s))

    def test_unscored_attack_windows_and_capture_edge_are_kept(self):
        s = model_stats(scored([("10:05", 9.0, True, "capture_edge"), ("09:00", 1.0, False, "capture_edge")]),
                        ATTACK, ATTACK)
        self.assertEqual(s["attack_unscored"], 1)
        self.assertEqual(s["attack_capture_edge"], [int(utc(10, 5))])
        self.assertEqual(s["normal_windows"], 0)  # capture_edge는 평소 창이 아니다
        self.assertFalse(is_distinct(s))

    def test_unit_without_normal_windows_has_null_distinct(self):
        t = Tables()
        t.score(A, "10:05", 9.0, True)
        self.assertIsNone(unit_of(run(t, episode("ep-1", ["10:05"])), A)["distinct_models"])

    def test_other_episode_windows_are_not_normal(self):
        # A_u: 같은 단위의 다른 에피소드 공격 창(11:00)은 평소 창에서 뺀다.
        t = Tables()
        t.score(A, "10:05", 5.0, True)
        t.score(A, "11:00", 8.0, True)
        t.normal(A, n=1, score=1.0)
        u = unit_of(run(t, episode("ep-1", ["10:05"]), episode("ep-2", ["11:00"], first="11:00:10")), A)
        self.assertEqual(u["models"][M1]["normal_windows"], 1)
        self.assertEqual(u["distinct_models"], [M1])
        self.assertTrue(u["few_normal_windows"])


def distinct_unit(t, unit, model=M1):
    """공격 창 10:05에서 후보이고 평소보다 높은 단위."""
    t.score(unit, "10:05", 5.0, True, model)
    t.normal(unit, score=1.0, model=model)


class AlertTest(unittest.TestCase):
    EP = episode("ep-1", ["10:05", "10:10"], units=(A,))

    def test_alert_whose_incident_overlapped_attack_at_alert_time(self):
        t = Tables()
        distinct_unit(t, A)
        inc = t.incident(A, "10:05", ["10:05"], job=5)
        t.incident(A, "10:05", ["10:05", "10:10"], job=10)
        t.slack(inc, 5, utc(10, 13))
        t.slack(inc, 5, utc(10, 12), version="llm-report.v1")  # 더 이른 행이 첫 알림
        u = unit_of(run(t, self.EP), A)
        a = u["first_alert"]
        self.assertEqual(a["report_version"], "llm-report.v1")
        self.assertEqual((a["job_id"], a["bundle_id"]), (5, None))  # job 5는 scoring_job에 없다
        self.assertAlmostEqual(a["latency_s"], utc(10, 12) - utc(10, 6, 16), places=3)
        # 창이 닫힌 뒤 = 알림 - (겹친 가장 이른 창 10:05의 끝 10:10)
        self.assertAlmostEqual(a["latency_after_window_close_s"], 120, places=3)
        self.assertEqual(u["attack_alert_count"], 2)
        self.assertEqual(u["queue"][0]["queue_rank"], 1)
        self.assertEqual(u["absorbed"], [])

    def test_incident_that_grows_onto_attack_later_is_absorbed_not_counted(self):
        t = Tables()
        distinct_unit(t, A)
        inc = t.incident(A, "09:55", ["09:55", "10:00"], job=5)  # 알림 시점에는 공격 창과 겹치지 않는다
        t.incident(A, "09:55", ["09:55", "10:00", "10:05"], job=10)  # J_c에서 공격 창까지 자랐다
        t.slack(inc, 5, utc(10, 7))
        u = unit_of(run(t, self.EP), A)
        self.assertIsNone(u["first_alert"])
        self.assertEqual([b["incident_id"] for b in u["absorbed"]], [inc])

    def test_alert_before_attack_start_is_not_counted(self):
        t = Tables()
        distinct_unit(t, A)
        inc = t.incident(A, "10:05", ["10:05"], job=5)
        t.slack(inc, 5, utc(10, 6, 15))  # t0 = 10:06:16 앞
        self.assertIsNone(unit_of(run(t, self.EP), A)["first_alert"])

    def test_status_rows_are_not_alerts(self):
        t = Tables()
        distinct_unit(t, A)
        inc = t.incident(A, "10:05", ["10:05"], job=10)
        t.slack(inc, 10, utc(10, 20), version="status:closed")
        u = unit_of(run(t, self.EP), A)
        self.assertIsNone(u["first_alert"])
        self.assertEqual(u["absorbed"], [])  # 상태 행만 있으면 알린 사건이 아니다

    def test_other_unit_rows_are_not_counted(self):
        t = Tables()
        distinct_unit(t, A)
        inc = t.incident(B, "10:05", ["10:05"], job=10)
        t.slack(inc, 10, utc(10, 12))
        self.assertIsNone(unit_of(run(t, self.EP), A)["first_alert"])


def delivery(created, parent="", broadcast="f"):
    return {"created": created, "thread_parent": parent, "reply_broadcast": broadcast}


class ChannelTest(unittest.TestCase):
    def test_before_thread_columns_is_unknown(self):
        self.assertIsNone(channel_visible(delivery(THREAD_INFO_SINCE - 1)))

    def test_head_alert_is_visible(self):
        self.assertTrue(channel_visible(delivery(THREAD_INFO_SINCE)))

    def test_reply_with_broadcast_is_visible(self):
        self.assertTrue(channel_visible(delivery(THREAD_INFO_SINCE + 1, parent="x", broadcast="t")))

    def test_reply_only_is_in_thread(self):
        self.assertFalse(channel_visible(delivery(THREAD_INFO_SINCE + 1, parent="x", broadcast="f")))


class VerdictTest(unittest.TestCase):
    def alerted(self, t, unit, minute):
        inc = t.incident(unit, "10:05", ["10:05"], job=10)
        t.slack(inc, 10, utc(10, minute))

    def test_detected(self):
        t = Tables()
        distinct_unit(t, A)
        self.alerted(t, A, 12)
        self.assertEqual(run(t, episode("ep-1", ["10:05"]))["episodes"][0]["verdict"], "detected")

    def test_indistinct_when_alert_but_not_distinct(self):
        t = Tables()
        t.score(A, "10:05", 5.0, True)
        t.normal(A, score=5.0)  # 같으면 구분 안 됨
        self.alerted(t, A, 12)
        ep = run(t, episode("ep-1", ["10:05"]))["episodes"][0]
        self.assertEqual(ep["verdict"], "indistinct")
        self.assertEqual(ep["first_alert"]["unit"], "10.0.0.50 originator")

    def test_indistinct_when_no_normal_windows(self):
        t = Tables()
        t.score(A, "10:05", 5.0, True)
        self.alerted(t, A, 12)
        self.assertEqual(run(t, episode("ep-1", ["10:05"]))["episodes"][0]["verdict"], "indistinct")

    def test_candidate_only_keeps_distinct_flag(self):
        t = Tables()
        distinct_unit(t, B)
        ep = run(t, episode("ep-1", ["10:05"]))["episodes"][0]
        self.assertEqual(ep["verdict"], "candidate_only")
        self.assertTrue(ep["has_distinct_model"])
        self.assertIsNone(ep["first_alert"])

    def test_missed_when_no_candidate(self):
        t = Tables()
        t.score(A, "10:05", 9.0, False)
        t.normal(A)
        self.assertEqual(run(t, episode("ep-1", ["10:05"]))["episodes"][0]["verdict"], "missed")

    def test_several_units_detected_time_uses_deciding_units_only(self):
        # A는 더 일찍 알렸지만 구분되지 않는다. B는 늦게 알렸고 구분된다 → 잡힘, 걸린 시간은 B 기준.
        t = Tables()
        t.score(A, "10:05", 5.0, True)
        t.normal(A, score=6.0)
        self.alerted(t, A, 11)
        distinct_unit(t, B, model=M2)
        self.alerted(t, B, 14)
        ep = run(t, episode("ep-1", ["10:05"]))["episodes"][0]
        self.assertEqual(ep["verdict"], "detected")
        self.assertEqual(ep["deciding_units"], ["10.0.0.20 responder"])
        self.assertEqual(ep["first_alert"]["unit"], "10.0.0.20 responder")
        self.assertEqual(ep["deciding_distinct_models"], [M2])

    def test_several_units_indistinct_uses_earliest_alert(self):
        t = Tables()
        for unit, minute in ((A, 13), (B, 11)):
            t.score(unit, "10:05", 5.0, True)
            self.alerted(t, unit, minute)
        ep = run(t, episode("ep-1", ["10:05"]))["episodes"][0]
        self.assertEqual(ep["verdict"], "indistinct")
        self.assertEqual(ep["first_alert"]["unit"], "10.0.0.20 responder")


class ScenarioTest(unittest.TestCase):
    def test_best_run_decides_scenario(self):
        runs = [{"scenario": "s", "run": 2, "episode_id": "e2", "verdict": "detected", "first_alert": None,
                 "deciding_distinct_models": []},
                {"scenario": "s", "run": 1, "episode_id": "e1", "verdict": "missed", "first_alert": None,
                 "deciding_distinct_models": []},
                {"scenario": "t", "run": 1, "episode_id": "e3", "verdict": "candidate_only", "first_alert": None,
                 "deciding_distinct_models": []},
                {"scenario": "t", "run": 2, "episode_id": "e4", "verdict": "indistinct", "first_alert": None,
                 "deciding_distinct_models": []}]
        summary = {s["scenario"]: s for s in summarize_scenarios(runs)}
        self.assertEqual(summary["s"]["best_verdict"], "detected")
        self.assertEqual([r["run"] for r in summary["s"]["per_run"]], [1, 2])
        self.assertEqual(summary["t"]["best_verdict"], "indistinct")


class QueueTest(unittest.TestCase):
    def test_same_unit_incident_outside_attack_is_not_queued_or_absorbed(self):
        t = Tables()
        distinct_unit(t, A)
        outside = t.incident(A, "09:00", ["09:00"], job=10, rank=1)
        inside = t.incident(A, "10:05", ["10:05"], job=10, rank=3)
        t.incident(B, "10:05", ["10:05"], job=10, rank=2)
        t.slack(outside, 10, utc(10, 20))
        u = unit_of(run(t, episode("ep-1", ["10:05"])), A)
        self.assertEqual([q["incident_id"] for q in u["queue"]], [inside])
        self.assertEqual(u["queue"][0]["incidents_in_job"], 3)  # J_c의 전체 사건 수
        self.assertEqual(u["absorbed"], [])

    def test_other_capture_incident_with_same_asset_role_is_not_queued(self):
        t = Tables()
        distinct_unit(t, A)
        t.incident(A, "10:05", ["10:05"], job=10, capture="lab-20291231")
        self.assertEqual(unit_of(run(t, episode("ep-1", ["10:05"])), A)["queue"], [])

    def test_incident_count_is_from_last_job(self):
        t = Tables()
        t.job(11, status="failed")
        distinct_unit(t, A)
        t.incident(A, "10:05", ["10:05"], job=10)
        t.incident(B, "10:05", ["10:05"], job=11)
        t.incident(B, "10:10", ["10:10"], job=11)
        result = run(t, episode("ep-1", ["10:05"]))
        self.assertEqual(result["captures"][CAP]["last_job_id"], 10)
        self.assertEqual(result["captures"][CAP]["incidents_in_job"], 1)


class AlertDetailTest(unittest.TestCase):
    EP = episode("ep-1", ["10:05", "10:10"], units=(A,))

    def test_close_time_uses_earliest_overlapping_window(self):
        # 알림 시점 사건 창이 둘째 공격 창(10:10)부터 겹치면 기준은 10:15다.
        t = Tables()
        distinct_unit(t, A)
        inc = t.incident(A, "10:10", ["10:10"], job=5)
        t.slack(inc, 5, utc(10, 17))
        a = unit_of(run(t, self.EP), A)["first_alert"]
        self.assertAlmostEqual(a["latency_after_window_close_s"], 120, places=3)

    def test_channel_visibility_reaches_unit_result(self):
        t = Tables()
        distinct_unit(t, A)
        inc = t.incident(A, "10:05", ["10:05"], job=5)
        t.slack(inc, 5, utc(10, 12), parent="other", broadcast="f")
        self.assertIs(unit_of(run(t, self.EP), A)["first_alert"]["channel_visible"], False)

    def test_alert_at_exactly_t0_is_counted(self):
        t = Tables()
        distinct_unit(t, A)
        inc = t.incident(A, "10:05", ["10:05"], job=5)
        t.slack(inc, 5, utc(10, 6, 16))
        self.assertEqual(unit_of(run(t, self.EP), A)["first_alert"]["latency_s"], 0)


class NormalWindowTest(unittest.TestCase):
    def test_attack_union_ignores_other_capture(self):
        # 날짜가 같은 다른 캡처의 에피소드 창(09:00)은 이 캡처의 평소 창에서 빼지 않는다.
        other = "lab-b-20300101"
        t = Tables()
        t.job(20, capture=other)
        t.score(A, "10:05", 5.0, True)
        t.normal(A, n=1)
        u = unit_of(run(t, episode("ep-1", ["10:05"]), episode("ep-2", ["09:00"], first="09:00:10",
                                                                capture=other)), A)
        self.assertEqual(u["normal_window_count"], 1)

    def test_few_normal_windows_threshold_is_below_five(self):
        for n, few in ((4, True), (5, False)):
            t = Tables()
            t.score(A, "10:05", 5.0, True)
            t.normal(A, n=n)
            self.assertEqual(unit_of(run(t, episode("ep-1", ["10:05"])), A)["few_normal_windows"], few)

    def test_failed_attempt_window_is_not_normal(self):
        t = Tables()
        t.score(A, "10:05", 5.0, True)
        t.score(A, "10:00", 9.0, True)  # 실패한 시도 창. 넣으면 평소 최고가 9가 된다
        t.normal(A, n=2, score=1.0)
        failed = {"capture_id": CAP, "kind": "failed_attempt", "units": [A], "windows_utc": ["10:00"]}
        u = unit_of(run(t, episode("ep-1", ["10:05"]), other_activity=[failed]), A)
        self.assertEqual(u["normal_window_count"], 2)
        self.assertEqual(u["failed_attempt_windows_excluded"], 1)
        self.assertEqual(u["distinct_models"], [M1])
        # 다른 단위에는 적용하지 않는다
        t.score(B, "10:05", 5.0, True)
        t.score(B, "10:00", 9.0, True)
        b = unit_of(run(t, episode("ep-1", ["10:05"]), other_activity=[failed]), B)
        self.assertEqual((b["normal_window_count"], b["failed_attempt_windows_excluded"]), (1, 0))

    def test_non_host_only_window_is_not_normal(self):
        # 큐 자격 규칙이 non_host_only로 뺀 창은 평소 창이 아니다(평소 최고 점수에도 들지 않는다). 뺀 수를 남긴다.
        t = Tables()
        t.score(A, "10:05", 5.0, True)
        t.score(A, "10:00", 9.0, True, split="non_host_only")
        t.score(A, "10:05", 7.0, True, model=M2, split="live")
        t.normal(A, n=2, score=1.0)
        u = unit_of(run(t, episode("ep-1", ["10:05"])), A)
        self.assertEqual(u["normal_window_count"], 2)
        self.assertEqual(u["non_host_only_windows_excluded"], 1)
        self.assertEqual(u["models"][M1]["normal_max"], 1.0)
        # 규칙이 없는 작업은 0이다
        t2 = Tables()
        t2.score(A, "10:05", 5.0, True)
        t2.normal(A, n=2)
        self.assertEqual(unit_of(run(t2, episode("ep-1", ["10:05"])), A)["non_host_only_windows_excluded"], 0)


class AbsorbedTest(unittest.TestCase):
    def test_absorbed_per_incident_even_when_unit_has_attack_alert(self):
        t = Tables()
        distinct_unit(t, A)
        old = t.incident(A, "09:55", ["09:55", "10:05", "10:10"], job=10, rank=2)  # 공격 전에 알린 사건
        new = t.incident(A, "10:15", ["10:15"], job=10, rank=1)
        t.incident(A, "10:15", ["10:15"], job=6)
        t.incident(A, "09:55", ["09:55"], job=4)
        t.slack(old, 4, utc(9, 59))  # t0 앞 알림
        ep = episode("ep-1", ["10:05", "10:10", "10:15"], units=(A,))
        t.slack(new, 6, utc(10, 18))
        u = unit_of(run(t, ep), A)
        self.assertEqual(u["first_alert"]["incident_id"], new)
        self.assertEqual([b["incident_id"] for b in u["absorbed"]], [old])
        self.assertEqual(u["absorbed"][0]["attack_windows_covered"], 2)
        self.assertEqual(u["absorbed"][0]["first_alert_at"], db(utc(9, 59)))
        self.assertTrue(u["partially_absorbed"])

    def test_incident_with_attack_alert_is_not_absorbed(self):
        t = Tables()
        distinct_unit(t, A)
        inc = t.incident(A, "09:55", ["09:55", "10:05"], job=10)
        t.incident(A, "09:55", ["09:55"], job=4)
        t.incident(A, "09:55", ["09:55", "10:05"], job=6)
        t.slack(inc, 4, utc(9, 59))
        t.slack(inc, 6, utc(10, 12))  # 같은 사건의 뒤 알림이 공격 창에서 나왔다
        u = unit_of(run(t, episode("ep-1", ["10:05"], units=(A,))), A)
        self.assertEqual(u["absorbed"], [])
        self.assertFalse(u["partially_absorbed"])


class SharedAlertTest(unittest.TestCase):
    def test_same_alert_row_used_by_two_episodes(self):
        t = Tables()
        distinct_unit(t, A)
        t.score(A, "10:10", 5.0, True)
        inc = t.incident(A, "10:05", ["10:05", "10:10"], job=5)
        t.slack(inc, 5, utc(10, 16))
        result = run(t, episode("ep-1", ["10:05"], units=(A,)),
                     episode("ep-2", ["10:10"], units=(A,), first="10:10:05"))
        self.assertEqual(unit_of(result, A, "ep-1")["first_alert"]["shared_with_episodes"], ["ep-2"])
        self.assertEqual(result["episodes"][1]["shares_alert_with"], ["ep-1"])

    def test_absorbed_into_other_episode_alert(self):
        # ep-1의 공격 창 알림을 낸 사건이 J_c에서 ep-2 창까지 자랐다.
        t = Tables()
        distinct_unit(t, A)
        t.score(A, "10:15", 5.0, True)
        t.incident(A, "10:05", ["10:05"], job=5)
        inc = t.incident(A, "10:05", ["10:05", "10:15"], job=10)
        t.slack(inc, 5, utc(10, 11))
        result = run(t, episode("ep-1", ["10:05"], units=(A,)),
                     episode("ep-2", ["10:15"], units=(A,), first="10:15:05"))
        u = unit_of(result, A, "ep-2")
        self.assertIsNone(u["first_alert"])
        self.assertEqual(u["absorbed"][0]["absorbed_into_episodes"], ["ep-1"])
        self.assertEqual(unit_of(result, A, "ep-1")["absorbed"], [])


class SummaryLatencyTest(unittest.TestCase):
    def test_per_run_latency_and_deciding_models(self):
        t = Tables()
        distinct_unit(t, A)
        distinct_unit(t, B, model=M2)  # B는 알림이 없다
        inc = t.incident(A, "10:05", ["10:05"], job=10)
        t.slack(inc, 10, utc(10, 12, 16))
        result = run(t, episode("ep-1", ["10:05"]))
        r = result["scenarios"][0]["per_run"][0]
        self.assertAlmostEqual(r["latency_s"], 360, places=3)
        self.assertEqual(r["deciding_distinct_models"], [M1])
        ep = result["episodes"][0]
        self.assertEqual(ep["non_deciding_distinct"], [{"unit": "10.0.0.20 responder", "models": [M2]}])
        self.assertEqual(ep["all_distinct_models"], [M1, M2])


CONFIG = {"config_id": "fake", "episodes": []}


def table_rows(text, title):
    """md에서 제목 다음 표의 머리글과 본문 행."""
    block = text.split(title, 1)[1].split("\n## ", 1)[0]
    rows = [line for line in block.splitlines() if line.startswith("|")]
    return rows[0], rows[2:]


class RenderTest(unittest.TestCase):
    def render(self):
        # ep-1: 잡힘(A 알림·구분, B 알림 없이 구분). ep-2: 구분 안 됨. ep-3: 놓침.
        t = Tables()
        distinct_unit(t, A)
        distinct_unit(t, B, model=M2)
        inc = t.incident(A, "10:05", ["10:05"], job=10)
        t.slack(inc, 10, utc(10, 12, 16))
        C = {"asset": "10.0.0.30", "role": "originator"}
        t.score(C, "11:00", 5.0, True)
        inc = t.incident(C, "11:00", ["11:00"], job=10)
        t.slack(inc, 10, utc(11, 20, 54))
        eps = [episode("ep-1", ["10:05"], scenario="s1"),
               episode("ep-2", ["11:00"], units=(C,), first="11:00:00", scenario="s2"),
               episode("ep-3", ["12:00"], units=(C,), first="12:00:00", scenario="s3")]
        result = run(t, *eps)
        return render_markdown(result, {**CONFIG, "episodes": eps}, "outputs/x"), result

    def test_tables_have_headers_and_rows(self):
        text, _ = self.render()
        head1, rows1 = table_rows(text, "## 표 1.")
        self.assertEqual(head1, "| 종류 | 실행 수 | 판정(실행별) | 걸린 시간(분) | 구분된 모델 | 비고 |")
        self.assertEqual(len(rows1), 3)
        head2, rows2 = table_rows(text, "## 표 2.")
        self.assertTrue(head2.startswith(f"| 에피소드 | 단위 | {M1} | {M2} | 큐 순위 |"))
        self.assertEqual(len(rows2), 4)  # ep-1 단위 2 + ep-2 단위 1 + ep-3 단위 1

    def test_latency_and_distinct_columns(self):
        text, _ = self.render()
        _, rows1 = table_rows(text, "## 표 1.")
        s1, s2, s3 = rows1
        self.assertIn("| 1: 6.0 |", s1)
        self.assertIn(f"| 1: {M1} |", s1)  # 판정을 만든 단위의 모델만
        self.assertIn(f"알림 없는 단위에서 구분: {M2}(10.0.0.20 responder)", s1)
        self.assertIn("| 1: (알림 20.9분, 구분 안 됨) |", s2)
        self.assertIn("| 1: — | 1: — |", s3)

    def test_tilde_is_escaped(self):
        text, _ = self.render()
        self.assertIn("1\\~2회", text)
        self.assertIsNone(re.search(r"(?<!\\)~", text))


if __name__ == "__main__":
    unittest.main()
