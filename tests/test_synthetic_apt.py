import random
import unittest

from zeek_ad.synthetic_apt import (
    Context, beacon_https, community_id, dns_tunnel, internal_scan, lateral_smb, slow_exfil, truth_windows,
)

DELAYS = {"tcp:SF": 5.0, "tcp:RSTO": 5.0, "tcp:REJ": 0.5, "udp:SF": 10.0}
DC = "192.168.10.3"


def ctx(seed=1):
    return Context(random.Random(seed), DELAYS, set())


class CommunityIdTest(unittest.TestCase):
    def test_matches_zeek_output(self):
        # run-02 화요일 conn.log의 실제 행(192.168.10.5:49182 → 192.168.10.3:88 tcp)과 같은 값이어야 한다.
        self.assertEqual(community_id("192.168.10.5", 49182, "192.168.10.3", 88, "tcp"),
                         "1:DKHkpl9baq8Q/fY8Fvym8YO0wMk=")

    def test_direction_independent(self):
        self.assertEqual(community_id("10.0.0.1", 1000, "10.0.0.2", 80, "tcp"),
                         community_id("10.0.0.2", 80, "10.0.0.1", 1000, "tcp"))


class PatternTest(unittest.TestCase):
    def test_beacon_interval_and_dns(self):
        p = {"duration_seconds": 3600, "interval_seconds": 300, "jitter": 0.2, "orig_bytes": [300, 700],
             "resp_bytes": [400, 1600], "conn_duration": [0.3, 1.5], "orig_pkts": [8, 12], "resp_pkts": [7, 11],
             "dns_every_seconds": 1800}
        ep = beacon_https(ctx(), "192.168.10.9", 1000.0, p, DC, "52.1.2.3", "abcdefgh.com")
        tls = [r for r in ep.logs["conn"] if r["id.resp_p"] == 443]
        gaps = [b["ts"] - a["ts"] for a, b in zip(tls, tls[1:])]
        self.assertTrue(all(240 - 1e-6 <= g <= 360 + 1e-6 for g in gaps))
        self.assertEqual(len(ep.logs["ssl"]), len(tls))
        self.assertGreaterEqual(len(ep.logs["dns"]), 2)  # 0분, 30분
        self.assertTrue(all(r["_write_ts"] > r["ts"] + r["duration"] for r in ep.logs["conn"]))

    def test_every_aux_row_has_conn(self):
        e = ctx()
        eps = [
            lateral_smb(e, "192.168.10.12", 0.0, {"targets": 2, "gap_seconds": [600, 1200],
                                                   "payload_bytes": [150000, 400000]}, DC,
                        ["192.168.10.5", "192.168.10.8"]),
            dns_tunnel(e, "192.168.10.9", 0.0, {"duration_seconds": 120, "interval_seconds": [5, 15],
                                                 "label_len": [40, 56], "qtype": "A"}, DC, "abcdefgh.net"),
            slow_exfil(e, "192.168.10.14", 0.0, {"duration_seconds": 1200, "interval_seconds": 600, "jitter": 0.2,
                                                  "orig_bytes": [3000000, 8000000], "resp_bytes": [5000, 20000],
                                                  "conn_duration": [20, 60], "dns_every_seconds": 1800},
                       DC, "52.1.2.4", "qwertyui.com"),
        ]
        uids = [r["uid"] for ep in eps for r in ep.logs["conn"]]
        self.assertEqual(len(uids), len(set(uids)))
        for ep in eps:
            conn_uids = {r["uid"] for r in ep.logs["conn"]}
            for log, rows in ep.logs.items():
                self.assertTrue({r["uid"] for r in rows} <= conn_uids, log)

    def test_lateral_has_admin_share_and_service_creation(self):
        ep = lateral_smb(ctx(), "192.168.10.12", 0.0, {"targets": 1, "gap_seconds": [600, 1200],
                                                        "payload_bytes": [150000, 400000]}, DC, ["192.168.10.5"])
        self.assertIn("\\\\192.168.10.5\\ADMIN$", [r["path"] for r in ep.logs["smb_mapping"]])
        self.assertIn("CreateServiceW", [r["operation"] for r in ep.logs["dce_rpc"]])
        self.assertEqual(ep.logs["kerberos"][0]["request_type"], "TGS")

    def test_scan_open_closed_and_truth_roles(self):
        p = {"ports": [22, 445], "interval_seconds": [60, 140]}
        ep = internal_scan(ctx(), "192.168.10.9", 0.0, p, ["192.168.10.5", "192.168.10.12"], ["192.168.10.12"])
        state = {(r["id.resp_h"], r["id.resp_p"]): r["conn_state"] for r in ep.logs["conn"]}
        self.assertEqual(state, {("192.168.10.5", 22): "REJ", ("192.168.10.5", 445): "RSTO",
                                 ("192.168.10.12", 22): "RSTO", ("192.168.10.12", 445): "REJ"})
        roles = {(a, r) for a, r, _ in truth_windows(ep, 300)}
        self.assertEqual(roles, {("192.168.10.9", "originator"), ("192.168.10.5", "responder"),
                                 ("192.168.10.12", "responder")})

    def test_deterministic(self):
        p = {"duration_seconds": 300, "interval_seconds": [5, 15], "label_len": [40, 56], "qtype": "A"}
        a = dns_tunnel(ctx(7), "192.168.10.9", 0.0, p, DC, "x.com").logs
        b = dns_tunnel(ctx(7), "192.168.10.9", 0.0, p, DC, "x.com").logs
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
