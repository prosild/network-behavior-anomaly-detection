"""조사 큐 자격 규칙(zeek_ad/queue_eligibility.py)과 worker 연결, 작업 식별, 전후 측정 스크립트의 큐 재현.

zeek-ad 환경에서 실행한다: python -m unittest tests.test_queue_eligibility -v
확인하는 것:
- 주소 판정: 내부 대역의 네트워크·브로드캐스트 주소, 255.255.255.255, 멀티캐스트(IPv4·IPv6)만 호스트가 아니다.
- 창 판정: 그 창의 연결이 전부 호스트가 아닌 주소행이고 그 수가 상한(25) 이하인 (출발 주소, 창)만 든다.
  26개면 들지 않고 "상한을 넘어 남긴 창"으로 따로 센다. 창은 _write_ts로 정한다.
- 라벨: originator 행만, capture_edge는 그대로, 세 모델 행 모두. 라벨 창은 큐에서 빠지고 양옆이 이어지지 않는다.
- 작업 입력 지문: 항목이 없으면 예전 계산과 같고, 있으면 규칙 설정·자산 설정·연결 자료에 따라 달라진다.
- live_agent.revision_for_job이 항목이 있는 리비전과 없는 옛 리비전을 모두 찾는다.
모든 값은 규칙 확인용 가짜 예제다(outputs·DB·네트워크를 쓰지 않는다).
"""

import hashlib
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from zeek_ad.bundle import FusionBundle  # noqa: E402
from zeek_ad.provenance import sha256  # noqa: E402
from zeek_ad.queue_eligibility import (  # noqa: E402
    apply_to_set, is_non_host_address, label_rows, label_scores, load_config, non_host_only_windows,
    scan_connections,
)
from zeek_ad.worker import input_fingerprint, set_input_fingerprint  # noqa: E402

NETS = (ipaddress.ip_network("10.10.0.0/24"),)
RULE = PROJECT_ROOT / "configs" / "worker" / "queue-eligibility.v1.json"
W = 300
LIMIT = 25
BCAST = "10.10.0.255"
MODELS = ["tgn_recon", "tail_rarity_v2", "transformer_v2"]


class AddressTest(unittest.TestCase):
    def test_non_host(self):
        for a in ["10.10.0.255", "10.10.0.0", "255.255.255.255", "224.0.0.251", "239.255.255.250", "ff02::fb"]:
            self.assertTrue(is_non_host_address(a, NETS), a)

    def test_host(self):
        # 다른 대역의 .255는 그 대역의 길이를 모르므로 호스트로 본다
        for a in ["10.10.0.20", "10.10.0.1", "192.168.1.255", "8.8.8.8", "fe80::1"]:
            self.assertFalse(is_non_host_address(a, NETS), a)

    def test_overlapping_networks_follow_asset_rule(self):
        # 10.0.0.0/8과 10.10.0.0/24가 함께 있으면 10.10.0.255는 자산(is_scored_asset 참)이므로 호스트다
        from zeek_ad.assets import is_scored_asset
        nets = (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("10.10.0.0/24"))
        for a, non_host in [("10.10.0.255", False), ("10.10.0.0", False), ("10.255.255.255", True),
                            ("10.0.0.0", True), ("10.10.0.20", False), ("224.0.0.251", True),
                            ("255.255.255.255", True), ("192.168.1.255", False)]:
            self.assertEqual(is_non_host_address(a, nets), non_host, a)
            if ipaddress.ip_address(a) in nets[0]:   # 내부 주소는 자산 규칙과 정확히 반대다
                self.assertEqual(non_host, not is_scored_asset(a, nets), a)

    def test_not_ip(self):
        for a in ["host-a", "", "10.10.0.256"]:
            with self.assertRaises(ValueError):
                is_non_host_address(a, NETS)

    def test_config_matches_code(self):
        config = load_config(RULE)
        self.assertEqual((config["label"], config["roles"]), ("non_host_only", ["originator"]))

    def test_config_rejects_unsupported_definition(self):
        config = json.loads(RULE.read_text(encoding="utf-8"))
        config["non_host_addresses"]["multicast"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rule.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


class WindowTest(unittest.TestCase):
    def test_all_broadcast_window(self):
        conns = [("10.10.0.20", BCAST, 10.0), ("10.10.0.20", "224.0.0.251", 20.0)]
        self.assertEqual(non_host_only_windows(conns, NETS, W, LIMIT), {("10.10.0.20", 0)})

    def test_one_host_connection_disqualifies(self):
        conns = [("10.10.0.20", BCAST, 10.0), ("10.10.0.20", "10.10.0.50", 290.0)]
        self.assertEqual(non_host_only_windows(conns, NETS, W, LIMIT), set())

    def test_window_from_write_ts(self):
        # 호스트행 연결의 _write_ts가 다음 창이면 앞 창은 브로드캐스트만 남는다
        conns = [("10.10.0.20", BCAST, 299.9), ("10.10.0.20", "10.10.0.50", 300.0)]
        self.assertEqual(non_host_only_windows(conns, NETS, W, LIMIT), {("10.10.0.20", 0)})

    def test_assets_are_separate(self):
        conns = [("10.10.0.20", BCAST, 10.0), ("10.10.0.21", BCAST, 10.0), ("10.10.0.21", "10.10.0.50", 20.0)]
        found, over, seen = scan_connections(conns, NETS, W, LIMIT)
        self.assertEqual(found, {("10.10.0.20", 0)})
        self.assertEqual(over, set())
        self.assertEqual(seen, {("10.10.0.20", 0), ("10.10.0.21", 0)})

    def test_connection_limit_boundary(self):
        # 상한 25: 25개는 뺌, 26개는 빼지 않고 상한을 넘은 창으로 센다
        at_limit = [("10.10.0.20", BCAST, 10.0 + i) for i in range(25)]
        above = [("10.10.0.21", BCAST, 10.0 + i) for i in range(26)]
        found, over, _ = scan_connections(at_limit + above, NETS, W, LIMIT)
        self.assertEqual(found, {("10.10.0.20", 0)})
        self.assertEqual(over, {("10.10.0.21", 0)})
        self.assertEqual(non_host_only_windows(above, NETS, W, 26), {("10.10.0.21", 0)})  # 상한은 인자로 받는다

    def test_config_limit(self):
        self.assertEqual(load_config(RULE)["max_connections"], 25)
        config = json.loads(RULE.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rule.json"
            for bad in (0, -1, 2.5, "25", True):
                config["max_connections"] = bad
                path.write_text(json.dumps(config), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_config(path)

    def test_empty(self):
        self.assertEqual(non_host_only_windows([], NETS, W, LIMIT), set())


def score_table(rows):
    """(자산, 역할, 창, split, 점수) → 세 모델 긴 표(bundle.score_capture 모양). 모든 모델에 같은 점수를 준다."""
    return pd.DataFrame([{"capture_id": "cap", "asset_id": a, "role": r, "window_start": w, "split": s,
                          "model_name": m, "score": sc, "is_candidate": sc >= 1.0}
                         for m in MODELS for a, r, w, s, sc in rows])


class LabelTest(unittest.TestCase):
    ROWS = [("10.10.0.20", "originator", 0, "capture_edge", 5.0), ("10.10.0.20", "originator", 300, "live", 5.0),
            ("10.10.0.20", "responder", 300, "live", 5.0), ("10.10.0.20", "originator", 600, "live", 5.0)]
    WINDOWS = {("10.10.0.20", 0), ("10.10.0.20", 300)}

    def test_label_scores(self):
        out = label_scores(score_table(self.ROWS), self.WINDOWS, "non_host_only")
        got = {(r.model_name, r.role, r.window_start): r.split for r in out.itertuples()}
        for m in MODELS:
            self.assertEqual(got[(m, "originator", 0)], "capture_edge")     # 캡처 끝 창은 그대로
            self.assertEqual(got[(m, "originator", 300)], "non_host_only")  # 세 모델 행 모두
            self.assertEqual(got[(m, "responder", 300)], "live")            # responder는 건드리지 않는다
            self.assertEqual(got[(m, "originator", 600)], "live")
        self.assertEqual(list(out.score), list(score_table(self.ROWS).score))  # 점수는 그대로

    def test_label_rows_same_rule(self):
        rows = [{"asset_id": a, "role": r, "window_start": w, "split": s} for a, r, w, s, _ in self.ROWS]
        out = label_rows(rows, self.WINDOWS, "non_host_only")
        self.assertEqual([r["split"] for r in out], ["capture_edge", "non_host_only", "live", "live"])
        self.assertEqual(rows[1]["split"], "live")  # 원래 행은 바꾸지 않는다

    def test_observed_check(self):
        with self.assertRaises(ValueError):  # 연결 자료에 없는 originator 창이면 다른 입력이다
            label_scores(score_table(self.ROWS), self.WINDOWS, "non_host_only", observed={("10.10.0.20", 0)})


def bundle(policy="merge_windows"):
    """load_context 없이 build_queue만 쓰는 묶음(임계값·결합 설정만 채운다)."""
    b = FusionBundle()
    b.thresholds = {m: 1.0 for m in MODELS}
    b.fusion = {"models": [{"name": m} for m in MODELS], "overlap_policy": policy}
    return b


class QueueTest(unittest.TestCase):
    def windows_of(self, fused):
        return [list(i.windows) for i in fused]

    def test_labeled_window_breaks_incident(self):
        rows = [("10.10.0.20", "originator", w, "live", 5.0) for w in (0, 300, 600)]
        labeled = label_scores(score_table(rows), {("10.10.0.20", 300)}, "non_host_only")
        fused, _, _ = bundle().build_queue(labeled[labeled.split != "non_host_only"], {"cap": "0" * 64})
        self.assertEqual(sorted(self.windows_of(fused)), [[0], [600]])
        # capture_edge로 뺀 것과 같은 동작이다
        edge = score_table([("10.10.0.20", "originator", w, "capture_edge" if w == 300 else "live", 5.0)
                            for w in (0, 300, 600)])
        same, _, _ = bundle().build_queue(edge, {"cap": "0" * 64})
        self.assertEqual([i.incident_id for i in fused], [i.incident_id for i in same])

    def test_apply_to_set_end_to_end(self):
        """worker 경로: Silver 읽기 → 라벨 → 큐 표. 항목이 없으면 표가 그대로다."""
        rows = [("10.10.0.20", "originator", 0, "live", 5.0), ("10.10.0.20", "originator", 300, "live", 5.0),
                ("10.10.0.50", "responder", 300, "live", 5.0)]
        scores = score_table(rows)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = write_rule_inputs(root, "cap", [("10.10.0.20", BCAST, 10.0), ("10.10.0.20", "10.10.0.50", 310.0)])
            labeled, queue, summary = apply_to_set(scores, {"queue_eligibility": entry}, "cap", root)
            plain = apply_to_set(scores, {}, "cap", root)
        self.assertEqual(summary, {"config_id": "queue-eligibility.v1", "label": "non_host_only", "max_connections": 25,
                                   "excluded_windows": 1, "over_limit_windows": 0})
        self.assertEqual(len(labeled), len(scores))
        self.assertEqual(sorted(set(zip(queue.asset_id, queue.role, queue.window_start))),
                         [("10.10.0.20", "originator", 300), ("10.10.0.50", "responder", 300)])
        self.assertIs(plain[0], scores)
        self.assertIs(plain[1], scores)
        self.assertIsNone(plain[2])

    def test_over_limit_window_stays_in_queue(self):
        """브로드캐스트만 26개인 창(폭주)은 라벨 없이 큐에 남아 사건이 된다. 25개인 창은 빠진다."""
        rows = [("10.10.0.20", "originator", 0, "live", 5.0), ("10.10.0.20", "originator", 300, "live", 5.0)]
        conns = ([("10.10.0.20", BCAST, 10.0 + i) for i in range(25)]
                 + [("10.10.0.20", BCAST, 310.0 + i) for i in range(26)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = write_rule_inputs(root, "cap", conns)
            labeled, queue, summary = apply_to_set(score_table(rows), {"queue_eligibility": entry}, "cap", root)
        self.assertEqual((summary["excluded_windows"], summary["over_limit_windows"]), (1, 1))
        self.assertEqual(set(labeled[labeled.window_start == 300].split), {"live"})
        fused, _, _ = bundle().build_queue(queue, {"cap": "0" * 64})
        self.assertEqual([list(i.windows) for i in fused], [[300]])


def write_rule_inputs(root, capture_id, conns, rule_text=None, assets_networks=("10.10.0.0/24",)):
    """규칙 설정·자산 설정·Silver(manifest + Parquet)를 root 아래에 쓰고 queue_eligibility 항목을 돌려준다."""
    (root / "rule.json").write_text(rule_text or RULE.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "assets.json").write_text(json.dumps({"internal_networks": list(assets_networks)}), encoding="utf-8")
    silver = root / "silver" / "conn_v1"
    part = silver / "conn" / f"capture_id={capture_id}"
    part.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(conns, columns=["orig_h", "resp_h", "write_ts"]).to_parquet(part / "part-0.parquet", index=False)
    (silver / "_manifests").mkdir(exist_ok=True)
    (silver / "_manifests" / f"{capture_id}.json").write_text(
        json.dumps({"capture_id": capture_id, "outputs": [sha256(part / "part-0.parquet")]}), encoding="utf-8")
    return {"config": "rule.json", "assets": "assets.json", "silver_dir": "silver/conn_v1"}


def write_scoring_inputs(d, n):
    for sub in ("gold", "graph"):
        (d / sub).mkdir(parents=True, exist_ok=True)
        (d / sub / "manifest.json").write_text(json.dumps({"n": n, "sub": sub}))
    (d / "bounds.json").write_text(json.dumps({"n": n}))
    return {"gold_dir": str(d / "gold"), "graph_dir": str(d / "graph"), "bounds": str(d / "bounds.json")}


class FingerprintTest(unittest.TestCase):
    def test_without_entry_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            cfg = write_scoring_inputs(d, 1)
            sha, record = set_input_fingerprint(cfg, "lab-x", d)
            old_sha, _ = input_fingerprint(d / "gold", d / "graph", d / "bounds.json", "lab-x")
            # 이 작업 전의 계산식(키 네 개)을 그대로 다시 계산해 견준다
            before = {"capture_id": "lab-x", "gold_manifest": sha256(d / "gold" / "manifest.json"),
                      "graph_manifest": sha256(d / "graph" / "manifest.json"), "bounds": sha256(d / "bounds.json")}
            expected = hashlib.sha256(json.dumps(before, sort_keys=True).encode("utf-8")).hexdigest()
        self.assertNotIn("queue_eligibility", record)
        self.assertEqual(sha, old_sha)
        self.assertEqual(sha, expected)

    def test_entry_changes_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            cfg = write_scoring_inputs(d, 1)
            plain = set_input_fingerprint(cfg, "lab-x", d)[0]
            entry = write_rule_inputs(d, "lab-x", [("10.10.0.20", BCAST, 10.0)])
            with_rule, record = set_input_fingerprint({**cfg, "queue_eligibility": entry}, "lab-x", d)
            self.assertNotEqual(with_rule, plain)
            self.assertEqual(set(record["queue_eligibility"]), {"config", "assets", "connections"})
            seen = {plain, with_rule}
            # 규칙 설정이 바뀌면
            write_rule_inputs(d, "lab-x", [("10.10.0.20", BCAST, 10.0)],
                              rule_text=RULE.read_text(encoding="utf-8").replace("2026-11-26", "2026-11-27"))
            seen.add(set_input_fingerprint({**cfg, "queue_eligibility": entry}, "lab-x", d)[0])
            # 연결 자료(Silver manifest)가 바뀌면
            write_rule_inputs(d, "lab-x", [("10.10.0.20", BCAST, 10.0), ("10.10.0.20", "10.10.0.50", 20.0)],
                              rule_text=RULE.read_text(encoding="utf-8").replace("2026-11-26", "2026-11-27"))
            seen.add(set_input_fingerprint({**cfg, "queue_eligibility": entry}, "lab-x", d)[0])
            # 자산 설정(내부 대역)이 바뀌면
            write_rule_inputs(d, "lab-x", [("10.10.0.20", BCAST, 10.0), ("10.10.0.20", "10.10.0.50", 20.0)],
                              rule_text=RULE.read_text(encoding="utf-8").replace("2026-11-26", "2026-11-27"),
                              assets_networks=("10.10.0.0/16",))
            seen.add(set_input_fingerprint({**cfg, "queue_eligibility": entry}, "lab-x", d)[0])
            # 설정의 연결 수 상한이 바뀌면
            limit_changed = json.loads(RULE.read_text(encoding="utf-8").replace("2026-11-26", "2026-11-27"))
            limit_changed["max_connections"] = 30
            write_rule_inputs(d, "lab-x", [("10.10.0.20", BCAST, 10.0), ("10.10.0.20", "10.10.0.50", 20.0)],
                              rule_text=json.dumps(limit_changed), assets_networks=("10.10.0.0/16",))
            seen.add(set_input_fingerprint({**cfg, "queue_eligibility": entry}, "lab-x", d)[0])
        self.assertEqual(len(seen), 6)

    def test_frozen_sets_have_no_entry(self):
        sets = json.loads((PROJECT_ROOT / "configs" / "worker" / "inputs.v1.json").read_text(encoding="utf-8"))["sets"]
        for name in ("cic", "synthetic"):
            self.assertNotIn("queue_eligibility", sets[name])


class RevisionForJobTest(unittest.TestCase):
    def test_finds_old_and_new_revisions(self):
        from live_agent import revision_for_job

        with tempfile.TemporaryDirectory() as tmp:
            cap = Path(tmp) / "lab-x"
            old, new, broken = cap / "rev-0001-aaaaaaaa", cap / "rev-0002-bbbbbbbb", cap / "rev-0003-cccccccc"
            cfg_old = write_scoring_inputs(old, 1)
            (old / "worker-inputs.json").write_text(json.dumps({"sets": {"live": cfg_old}}))
            cfg_new = write_scoring_inputs(new, 2)
            entry = write_rule_inputs(new, "lab-x", [("10.10.0.20", BCAST, 10.0)])
            entry = {k: str(new / v) for k, v in entry.items()}
            (new / "worker-inputs.json").write_text(json.dumps({"sets": {"live": {**cfg_new, "queue_eligibility": entry}}}))
            # 연결 자료가 끊긴 리비전(Silver manifest 없음)은 건너뛴다
            cfg_broken = write_scoring_inputs(broken, 3)
            (broken / "worker-inputs.json").write_text(json.dumps({"sets": {"live": {
                **cfg_broken, "queue_eligibility": {**entry, "silver_dir": str(broken / "missing")}}}}))
            old_sha = input_fingerprint(old / "gold", old / "graph", old / "bounds.json", "lab-x")[0]
            new_sha = set_input_fingerprint({**cfg_new, "queue_eligibility": entry}, "lab-x")[0]
            self.assertEqual(revision_for_job(cap, "lab-x", old_sha), old)
            self.assertEqual(revision_for_job(cap, "lab-x", new_sha), new)
            # 같은 리비전이라도 규칙 없이 만든 지문으로는 새 리비전을 찾지 않는다(다른 작업이다)
            plain_new = input_fingerprint(new / "gold", new / "graph", new / "bounds.json", "lab-x")[0]
            self.assertIsNone(revision_for_job(cap, "lab-x", plain_new))


class LiveRecomputeEntryTest(unittest.TestCase):
    """live_recompute.write_worker_inputs: 항목을 넣고, 규칙·자산 설정은 리비전 안 사본을 가리킨다."""

    DIRS = ("gold", "graph", "bounds", "events", "zeek", "silver")

    def make_public(self, root):
        """공용 설정(규칙·자산)을 root에 둔다. 반환: live.v1.json 모양의 설정."""
        (root / "rule.json").write_text(RULE.read_text(encoding="utf-8"), encoding="utf-8")
        (root / "assets.json").write_text(json.dumps({"internal_networks": ["10.10.0.0/24"]}), encoding="utf-8")
        return {"assets": "assets.json", "queue_eligibility": {"enabled": True, "config": "rule.json"}}

    def make_rev(self, cap, name, n):
        """리비전 하나의 채점 입력(Gold·그래프·bounds)과 Silver. 반환: write_worker_inputs의 dirs."""
        rev = cap / name
        cfg = write_scoring_inputs(rev, n)
        entry = write_rule_inputs(rev, "lab-x", [("10.10.0.20", BCAST, 10.0 + n)])
        return rev, {"gold": cfg["gold_dir"], "graph": cfg["graph_dir"], "bounds": cfg["bounds"],
                     "events": str(rev / "events"), "zeek": str(rev / "zeek"), "silver": str(rev / entry["silver_dir"])}

    def test_entry_written_with_revision_copies(self):
        from live_recompute import write_worker_inputs

        with tempfile.TemporaryDirectory() as tmp:
            public = Path(tmp) / "public"
            public.mkdir()
            config = self.make_public(public)
            rev, dirs = self.make_rev(Path(tmp) / "lab-x", "rev-0001-aaaaaaaa", 1)
            body = write_worker_inputs(rev / "worker-inputs.json", "lab-x", rev, dirs, config, public)
            entry = body["sets"]["live"]["queue_eligibility"]
            self.assertEqual(json.loads((rev / "worker-inputs.json").read_text(encoding="utf-8")), body)
            self.assertEqual(Path(entry["config"]), rev / "queue_eligibility" / "rule.json")
            self.assertEqual(Path(entry["assets"]), rev / "queue_eligibility" / "assets.json")
            self.assertEqual(entry["silver_dir"], dirs["silver"])
            self.assertEqual(sha256(entry["config"]), sha256(public / "rule.json"))
            off = write_worker_inputs(rev / "off.json", "lab-x", rev, dirs,
                                      {**config, "queue_eligibility": {"enabled": False}}, public)
            self.assertNotIn("queue_eligibility", off["sets"]["live"])
        live = json.loads((PROJECT_ROOT / "configs" / "pipeline" / "live.v1.json").read_text(encoding="utf-8"))
        self.assertTrue(live["queue_eligibility"]["enabled"])

    def test_default_when_key_missing(self):
        from live_recompute import queue_eligibility_entry

        with tempfile.TemporaryDirectory() as tmp:
            entry = queue_eligibility_entry({"assets": "configs/assets.lab.v1.json"}, Path(tmp), "s", PROJECT_ROOT)
            self.assertEqual(sha256(entry["config"]), sha256(RULE))   # 키가 없으면 기본 규칙 설정을 켠다

    def test_public_config_change_keeps_revision_fingerprint(self):
        from live_agent import revision_for_job
        from live_recompute import write_worker_inputs

        with tempfile.TemporaryDirectory() as tmp:
            public, cap = Path(tmp) / "public", Path(tmp) / "lab-x"
            public.mkdir()
            config = self.make_public(public)
            rev1, dirs1 = self.make_rev(cap, "rev-0001-aaaaaaaa", 1)
            body = write_worker_inputs(rev1 / "worker-inputs.json", "lab-x", rev1, dirs1, config, public)
            sha1 = set_input_fingerprint(body["sets"]["live"], "lab-x")[0]
            # 공용 규칙 설정(상한)과 자산 설정을 고친다
            changed = json.loads(RULE.read_text(encoding="utf-8"))
            changed["max_connections"] = 30
            (public / "rule.json").write_text(json.dumps(changed), encoding="utf-8")
            (public / "assets.json").write_text(json.dumps({"internal_networks": ["10.10.0.0/16"]}), encoding="utf-8")
            self.assertEqual(revision_for_job(cap, "lab-x", sha1), rev1)
            # 같은 리비전을 다시 돌려도(worker-inputs.json을 다시 써도) 사본을 덮어쓰지 않는다
            again = write_worker_inputs(rev1 / "worker-inputs.json", "lab-x", rev1, dirs1, config, public)
            self.assertEqual(set_input_fingerprint(again["sets"]["live"], "lab-x")[0], sha1)
            self.assertEqual(revision_for_job(cap, "lab-x", sha1), rev1)
            # 새 리비전은 새 설정의 사본과 새 지문을 갖는다
            rev2, dirs2 = self.make_rev(cap, "rev-0002-bbbbbbbb", 1)
            new = write_worker_inputs(rev2 / "worker-inputs.json", "lab-x", rev2, dirs2, config, public)
            sha2 = set_input_fingerprint(new["sets"]["live"], "lab-x")[0]
            self.assertEqual(load_config(new["sets"]["live"]["queue_eligibility"]["config"])["max_connections"], 30)
            self.assertNotEqual(sha2, sha1)   # Gold·Silver는 rev1과 같은 내용이고 설정만 다르다
            self.assertEqual(revision_for_job(cap, "lab-x", sha2), rev2)


class FakeModel:
    """score_capture는 정해 둔 표를 돌려주고, build_queue는 받은 표를 기록한다(bundle.build_queue 계산은 그대로)."""

    def __init__(self, scores):
        self.scores, self.queue_input = scores, None

    def score_capture(self, capture_id, gold_dir, graph_dir, packet_time_min):
        return self.scores

    def build_queue(self, scores, capture_sha):
        self.queue_input = scores
        return bundle().build_queue(scores, capture_sha)


class RunWorkerTest(unittest.TestCase):
    """run_worker의 점수 → 규칙 → 큐 → 쓸 표, 작업 지문(DB·MLflow 없이)."""

    ROWS = [("10.10.0.20", "originator", w, "live", 5.0) for w in (0, 300, 600)]
    CONNS = [("10.10.0.20", BCAST, 10.0), ("10.10.0.20", BCAST, 310.0), ("10.10.0.20", "10.10.0.50", 610.0)]

    def setUp(self):
        import run_worker
        self.rw = run_worker
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = {**write_scoring_inputs(self.root, 1),
                    "queue_eligibility": write_rule_inputs(self.root, "cap", self.CONNS)}
        self.bound = {"packet_time_min": "0", "pcap_sha256": "0" * 64}

    def tearDown(self):
        self.tmp.cleanup()

    def test_queue_gets_table_without_labeled_windows(self):
        model = FakeModel(score_table(self.ROWS))
        job = self.rw.score_job(model, self.cfg, "cap", self.bound, self.root)
        self.assertNotIn("non_host_only", set(model.queue_input.split))
        self.assertEqual(sorted(set(model.queue_input.window_start)), [600])
        self.assertEqual([list(i.windows) for i in job["fused"]], [[600]])
        self.assertEqual(job["eligibility"]["excluded_windows"], 2)

    def test_written_scores_are_full_labeled_table(self):
        from unittest import mock

        job = self.rw.score_job(FakeModel(score_table(self.ROWS)), self.cfg, "cap", self.bound, self.root)
        with mock.patch.object(self.rw, "write_results") as write:
            self.rw.store_job("conn", 7, job)
        written = write.call_args.args[2]
        self.assertEqual(len(written), len(self.ROWS) * 3)          # 라벨 창 행도 DB에 남는다
        self.assertEqual(sorted(written[written.split == "non_host_only"].window_start.unique()), [0, 300])
        self.assertEqual(write.call_args.args[3], job["fused"])

    def test_without_entry_nothing_changes(self):
        model = FakeModel(score_table(self.ROWS))
        cfg = {k: v for k, v in self.cfg.items() if k != "queue_eligibility"}
        job = self.rw.score_job(model, cfg, "cap", self.bound, self.root)
        self.assertIs(model.queue_input, model.scores)
        self.assertIs(job["scores"], model.scores)
        self.assertEqual([list(i.windows) for i in job["fused"]], [[0, 300, 600]])

    def test_job_fingerprint_includes_rule(self):
        plain = {k: v for k, v in self.cfg.items() if k != "queue_eligibility"}
        with_rule = self.rw.job_input_sha(self.cfg, "cap", self.root)
        self.assertNotEqual(with_rule, self.rw.job_input_sha(plain, "cap", self.root))
        self.assertEqual(with_rule, set_input_fingerprint(self.cfg, "cap", self.root)[0])
        self.assertEqual(self.rw.job_input_sha(plain, "cap", self.root),
                         input_fingerprint(self.root / "gold", self.root / "graph", self.root / "bounds.json", "cap")[0])

    def test_silver_and_gold_mismatch_stops(self):
        # Silver에 600초 창의 연결이 없다. 연결 자료가 Gold와 다른 입력이므로 멈춰야 한다
        write_rule_inputs(self.root, "cap", self.CONNS[:2])
        with self.assertRaises(ValueError):
            apply_to_set(score_table(self.ROWS), self.cfg, "cap", self.root)


class MeasureReproductionTest(unittest.TestCase):
    """측정 스크립트가 DB 사건을 저장된 창 점수로 다시 만드는 로직(작은 가짜 표)."""

    def setUp(self):
        import measure_queue_eligibility as mq
        self.mq = mq
        t = "2026-11-22 14:{:02d}:00+00"
        # 자산 A originator: 14:00·14:05·14:10 후보, 14:05는 브로드캐스트만. B responder: 14:00 후보
        self.window_score = [
            {"job_id": "7", "model_name": m, "asset_id": a, "role": r, "window_start": t.format(mm), "split": "live",
             "score": "5.0", "is_candidate": "t"}
            for m in MODELS for a, r, mm in [("10.10.0.20", "originator", 0), ("10.10.0.20", "originator", 5),
                                             ("10.10.0.20", "originator", 10), ("10.10.0.50", "responder", 0)]]
        self.thresholds = {m: 1.0 for m in MODELS}
        self.sha = {"lab-20261122": "0" * 64}
        self.base = 1795356000  # 2026-11-22 14:00 UTC

    def test_rebuild_matches_stored(self):
        mq = self.mq
        rows = mq.score_rows(self.window_score, 7, "lab-20261122")
        rebuilt = mq.rebuild_queue(rows, self.thresholds, MODELS, "merge_windows", self.sha)
        incidents = [{"job_id": "7", "incident_id": i["incident_id"], "queue_rank": str(i["rank"]),
                      "asset_id": i["asset_id"], "role": i["role"]} for i in rebuilt]
        windows = [{"job_id": "7", "incident_id": i["incident_id"],
                    "window_start": f"2026-11-22 14:{(w - self.base) // 60:02d}:00+00"}
                   for i in rebuilt for w in i["windows"]]
        stored = mq.stored_queue(incidents, windows, 7)
        self.assertEqual(mq.queue_differences(rebuilt, stored), [])
        self.assertEqual(sorted(len(i["windows"]) for i in rebuilt), [1, 3])  # 같은 점수라 순서는 동점 해시가 정한다
        swapped = [{**stored[0], "rank": 2}, {**stored[1], "rank": 1}]
        self.assertTrue(mq.queue_differences(rebuilt, swapped))

    def test_over_limit_kept_ignores_capture_edge(self):
        mq = self.mq
        rows = [{"asset_id": "10.10.0.20", "role": "originator", "window_start": w, "split": s}
                for w, s in ((0, "capture_edge"), (300, "live"), (600, "live"))]
        rows.append({"asset_id": "10.10.0.20", "role": "responder", "window_start": 600, "split": "live"})
        over = {("10.10.0.20", 0), ("10.10.0.20", 300)}
        self.assertEqual(mq.over_limit_kept(rows, over), {("10.10.0.20", 300)})

    def test_before_after(self):
        mq = self.mq
        rows = mq.score_rows(self.window_score, 7, "lab-20261122")
        labeled_set = {("10.10.0.20", self.base + 300)}
        before = mq.rebuild_queue(rows, self.thresholds, MODELS, "merge_windows", self.sha)
        after = mq.rebuild_queue(label_rows(rows, labeled_set, "non_host_only"), self.thresholds, MODELS,
                                 "merge_windows", self.sha, ("capture_edge", "non_host_only"))
        cmp = mq.compare_queues(before, after, labeled_set)
        self.assertEqual((cmp["incidents_before"], cmp["incidents_after"]), (2, 3))
        self.assertEqual([s["kind"] for s in cmp["scope_changed"]], ["split"])  # 가운데 창이 빠져 둘로 쪼개진다
        self.assertEqual(cmp["removed"], [])
        self.assertEqual(cmp["unchanged"], 1)


if __name__ == "__main__":
    unittest.main()
