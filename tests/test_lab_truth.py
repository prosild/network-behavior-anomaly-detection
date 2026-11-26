from datetime import datetime, timezone
import unittest

from zeek_ad.lab_truth import (
    attack_start, attack_windows, config_problems, conn_record, episode_connections, failed_attempt_windows,
    load_config, observe, overlapping_connections, rule_matches,
)


# 규칙 확인용 가짜 예제다. 실제 실습망 기록이 아니다.
CAP = "lab-20300101"
W = 300


def utc(h, m, s=0.0):
    return datetime(2030, 1, 1, h, m, tzinfo=timezone.utc).timestamp() + s


def conn(uid, ts, write_ts=None, folder="f1", orig="10.0.0.50", resp="10.0.0.20", resp_p=22, proto="tcp",
         capture=CAP):
    raw = {"uid": uid, "ts": ts, "_write_ts": ts + 1 if write_ts is None else write_ts,
           "id.orig_h": orig, "id.resp_h": resp, "id.resp_p": resp_p, "proto": proto}
    return conn_record(capture, folder, raw)


RULE = {"capture_id": CAP, "orig_h": ["10.0.0.50"], "resp_h": ["10.0.0.20", "10.0.0.21"],
        "ts_start_utc": "2030-01-01T10:00:00Z", "ts_end_utc": "2030-01-01T10:10:00Z"}


def episode(*rules):
    return {"episode_id": "ep-x", "rules": list(rules),
            "observed": {"first_ts_utc": "2030-01-01T10:06:16Z", "windows_utc": ["10:05", "10:10"]}}


class RuleTest(unittest.TestCase):
    def test_time_range_includes_start_and_excludes_end(self):
        self.assertTrue(rule_matches(RULE, conn("a", utc(10, 0))))
        self.assertFalse(rule_matches(RULE, conn("b", utc(10, 0) - 0.000001)))
        self.assertTrue(rule_matches(RULE, conn("c", utc(10, 9, 59.999))))
        self.assertFalse(rule_matches(RULE, conn("d", utc(10, 10))))

    def test_hosts_and_capture_must_match(self):
        self.assertTrue(rule_matches(RULE, conn("a", utc(10, 1), resp="10.0.0.21")))
        self.assertFalse(rule_matches(RULE, conn("b", utc(10, 1), resp="10.0.0.22")))
        self.assertFalse(rule_matches(RULE, conn("c", utc(10, 1), orig="10.0.0.20", resp="10.0.0.50")))
        self.assertFalse(rule_matches(RULE, conn("d", utc(10, 1), capture="lab-20300102")))

    def test_missing_resp_p_and_proto_mean_any(self):
        self.assertTrue(rule_matches(RULE, conn("a", utc(10, 1), resp_p=53, proto="udp")))
        self.assertTrue(rule_matches(RULE, conn("b", utc(10, 1), resp_p=None, proto="icmp")))

    def test_resp_p_and_proto_filter_when_present(self):
        rule = {**RULE, "resp_p": [139, 445], "proto": "tcp"}
        self.assertTrue(rule_matches(rule, conn("a", utc(10, 1), resp_p=445)))
        self.assertFalse(rule_matches(rule, conn("b", utc(10, 1), resp_p=22)))
        self.assertFalse(rule_matches(rule, conn("c", utc(10, 1), resp_p=445, proto="udp")))


class ConnectionsTest(unittest.TestCase):
    def test_same_uid_in_different_folders_counts_twice(self):
        rows = [conn("C1", utc(10, 1), folder="f1"), conn("C1", utc(10, 6), folder="f2")]
        self.assertEqual(len(episode_connections(episode(RULE), rows)), 2)

    def test_connection_matching_two_rules_counts_once(self):
        rows = [conn("C1", utc(10, 1))]
        self.assertEqual(len(episode_connections(episode(RULE, dict(RULE)), rows)), 1)


class ObserveTest(unittest.TestCase):
    def test_window_comes_from_write_ts_not_ts(self):
        # 10:04:59에 시작해 10:05:03에 기록된 연결은 10:05 창이다.
        rows = [conn("a", utc(10, 4, 59.5), write_ts=utc(10, 5, 3)), conn("b", utc(10, 1, 0.7))]
        got = observe(rows, CAP, W)
        self.assertEqual(got["windows_utc"], ["10:00", "10:05"])
        self.assertEqual(got["connections_per_window"], {"10:00": 1, "10:05": 1})
        self.assertEqual(got["connections"], 2)
        # 첫·끝 시각은 ts를 초 아래 버린 값이다.
        self.assertEqual(got["first_ts_utc"], "2030-01-01T10:01:00Z")
        self.assertEqual(got["last_ts_utc"], "2030-01-01T10:04:59Z")

    def test_window_outside_capture_date_is_rejected(self):
        rows = [conn("a", utc(23, 59, 59), write_ts=utc(23, 59, 59) + 5)]
        with self.assertRaises(ValueError):
            observe(rows, CAP, W)

    def test_attack_windows_and_start_use_capture_date(self):
        ep = episode(RULE)
        self.assertEqual(attack_windows(ep), [int(utc(10, 5)), int(utc(10, 10))])
        self.assertEqual(attack_start(ep), utc(10, 6, 16))


class ConfigFormatTest(unittest.TestCase):
    def test_repository_config_is_well_formed(self):
        config = load_config()
        self.assertEqual(config_problems(config), [])
        ids = [ep["episode_id"] for ep in config["episodes"]]
        self.assertEqual(len(ids), len(set(ids)))
        for ep in config["episodes"]:
            obs = ep["observed"]
            self.assertIn(ep["status"], ("confirmed", "uncertain", "unsupported"))
            self.assertEqual(obs["windows_utc"], sorted(obs["windows_utc"]))
            self.assertEqual(sum(obs["connections_per_window"].values()), obs["connections"])

    def test_problems_are_reported(self):
        good = {"episode_id": "a", "status": "confirmed", "rules": [RULE],
                "expected_units": [{"asset": "10.0.0.50", "role": "originator"}],
                "observed": {"connections": 3, "first_ts_utc": "2030-01-01T10:01:00Z",
                             "last_ts_utc": "2030-01-01T10:06:00Z", "windows_utc": ["10:00", "10:05"],
                             "connections_per_window": {"10:00": 1, "10:05": 2}}}
        self.assertEqual(config_problems({"window_seconds": W, "episodes": [good]}), [])
        bad = {**good, "status": "maybe",
               "observed": {**good["observed"], "windows_utc": ["10:05", "10:00"],
                            "connections_per_window": {"10:05": 2, "10:00": 2}}}
        problems = config_problems({"window_seconds": W, "episodes": [good, bad]})
        text = "\n".join(problems)
        for word in ("중복", "status", "정렬", "합"):
            self.assertIn(word, text)


class OverlapTest(unittest.TestCase):
    def test_connection_in_two_episodes_is_reported(self):
        shared = conn("C1", utc(10, 1), folder="f1")
        got = overlapping_connections({
            "ep-a": [shared, conn("C2", utc(10, 2))],
            "ep-b": [conn("C1", utc(10, 1), folder="f1")],
            "ep-c": [conn("C1", utc(10, 1), folder="f2")],  # 폴더가 다르면 다른 연결
        })
        self.assertEqual(got, {(CAP, "f1", "C1"): ["ep-a", "ep-b"]})

    def test_no_overlap_is_empty(self):
        self.assertEqual(overlapping_connections({"ep-a": [conn("C1", utc(10, 1))],
                                                  "ep-b": [conn("C2", utc(10, 1))]}), {})


FAILED = {"capture_id": CAP, "kind": "failed_attempt", "units": [{"asset": "10.0.0.20", "role": "originator"}],
          "windows_utc": ["14:00"]}


class FailedAttemptTest(unittest.TestCase):
    def test_windows_per_unit(self):
        got = failed_attempt_windows({"other_activity": [FAILED, {"capture_id": CAP, "kind": "check"}]})
        self.assertEqual(got, {(CAP, "10.0.0.20", "originator"): {int(utc(14, 0))}})

    def test_failed_attempt_needs_units_and_windows(self):
        for missing in ("capture_id", "units", "windows_utc"):
            item = {k: v for k, v in FAILED.items() if k != missing}
            problems = config_problems({"window_seconds": W, "episodes": [], "other_activity": [item]})
            self.assertTrue(any(missing in p for p in problems), missing)
        self.assertEqual(config_problems({"window_seconds": W, "episodes": [], "other_activity": [FAILED]}), [])

    def test_repository_config_has_failed_attempt_windows(self):
        self.assertTrue(failed_attempt_windows(load_config()))


if __name__ == "__main__":
    unittest.main()
