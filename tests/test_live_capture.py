"""실습망 캡처 준비(zeek_ad.live_capture) 시험.

만든 설정을 배치 코드(role_windows.load_captures)가 읽는지 확인하므로 pyspark가 있는 zeek-ad 환경에서 실행한다.
실행: python -m unittest tests.test_live_capture -v
"""

import json
from pathlib import Path
import tempfile
import unittest

from zeek_ad.live_capture import (PRUNE_LOG, capture_config, merge_zeek, observed_until, prune_revisions,
                                  revision_id, revisions_to_prune)
from zeek_ad.role_windows import load_captures
from zeek_ad.windows import label_window


def zeek_run(root, name, conn_rows, config_sha="c1"):
    """가짜 Zeek 실행 폴더: conn.log(JSON 줄), packet_filter.log, run-manifest.json."""
    d = Path(root) / name
    d.mkdir()
    (d / "conn.log").write_text("".join(json.dumps({"uid": u}) + "\n" for u in conn_rows))
    (d / "packet_filter.log").write_text('{"ts": 1}\n')
    (d / "run-manifest.json").write_text(json.dumps({
        "config": {"sha256": config_sha}, "image": "zeek@x", "zeek_version": "8.0.10", "scripts": [], "seed_file": {}}))
    return str(d)


def file_row(sha, run_dir, first, last, covered_to=None):
    return {"sha256": sha, "name": f"{sha}.pcap", "zeek_run_dir": run_dir, "packets": 10, "first": first, "last": last,
            "covered_to": covered_to}


class LiveCaptureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = [file_row("aa", zeek_run(self.root, "f1", ["C1", "C2"]), 100.0, 399.5),
                      file_row("bb", zeek_run(self.root, "f2", ["C3"]), 400.0, 699.0)]

    def test_revision_changes_only_with_file_set(self):
        self.assertEqual(revision_id(self.files), revision_id(list(reversed(self.files))))
        self.assertTrue(revision_id(self.files).startswith("rev-0002-"))
        self.assertNotEqual(revision_id(self.files), revision_id(self.files[:1]))

    def test_merge_keeps_file_order_and_counts(self):
        out = self.root / "rev" / "zeek"
        m = merge_zeek(self.files, out)
        uids = [json.loads(line)["uid"] for line in (out / "conn.log").read_text().splitlines()]
        self.assertEqual(uids, ["C1-aa", "C2-aa", "C3-bb"])
        self.assertEqual([o["name"] for o in m["outputs"]], ["conn.log"])     # packet_filter.log는 합치지 않는다
        self.assertEqual(m["outputs"][0]["rows"], 3)
        self.assertFalse(out.with_name("zeek.tmp").exists())
        with self.assertRaises(FileExistsError):                              # 완성된 폴더는 덮어쓰지 않는다
            merge_zeek(self.files, out)

    def test_same_uid_in_two_files_stays_distinct(self):
        # Zeek seed를 고정하면 파일마다 같은 uid가 나온다. 합친 뒤에는 겹치지 않아야 한다.
        files = [file_row("aa" * 32, zeek_run(self.root, "s1", ["C1", "C2"]), 100.0, 399.0),
                 file_row("bb" * 32, zeek_run(self.root, "s2", ["C1"]), 400.0, 699.0)]
        for f in files:
            d = Path(f["zeek_run_dir"])
            (d / "http.log").write_text(json.dumps({"uid": "C1", "resp_fuids": ["F1"], "status_code": 200}) + "\n")
        out = self.root / "rev2" / "zeek"
        merge_zeek(files, out)
        conn = [json.loads(line)["uid"] for line in (out / "conn.log").read_text().splitlines()]
        self.assertEqual(conn, ["C1-aaaaaa", "C2-aaaaaa", "C1-bbbbbb"])
        http = [json.loads(line) for line in (out / "http.log").read_text().splitlines()]
        self.assertEqual([h["uid"] for h in http], ["C1-aaaaaa", "C1-bbbbbb"])
        self.assertEqual(http[1]["resp_fuids"], ["F1-bbbbbb"])
        self.assertEqual(http[1]["status_code"], 200)                          # 다른 필드는 그대로

    def test_mixed_zeek_config_is_rejected(self):
        files = self.files + [file_row("cc", zeek_run(self.root, "f3", ["C4"], config_sha="c2"), 700.0, 900.0)]
        with self.assertRaises(ValueError):
            merge_zeek(files, self.root / "rev" / "zeek")

    def test_capture_config_is_readable_by_batch_code(self):
        rev = self.root / "rev"
        rev.mkdir()
        cfg, bounds = capture_config("lab-20261201", self.files, rev / "zeek", rev)
        captures = load_captures(cfg, bounds)
        self.assertEqual(captures, {"lab-20261201": {"usage": "live", "packet_time_min": 100.0,
                                                     "packet_time_max": 699.0}})
        # 다 받은 창은 live, 아직 다 받지 않은 마지막 창은 capture_edge(채점 큐에서 빠진다)
        self.assertEqual(label_window(300, 300, 100.0, 699.0, "live", 0.8), "live")          # 300~600초
        self.assertEqual(label_window(600, 300, 100.0, 699.0, "live", 0.8), "capture_edge")  # 600~900초, 699초까지만 받음

    def test_coverage_end_completes_last_window(self):
        # DD-016: 마지막 패킷은 699초지만 수집기가 900초까지 관측했다 → 600~900초 창도 다 관측한 창(live)
        files = [self.files[0], file_row("bb", self.files[1]["zeek_run_dir"], 400.0, 699.0, covered_to=900.0)]
        self.assertEqual(observed_until(files), 900.0)
        rev = self.root / "rev-cov"
        rev.mkdir()
        cfg, bounds = capture_config("lab-20261201", files, rev / "zeek", rev)
        cap = load_captures(cfg, bounds)["lab-20261201"]
        self.assertEqual((cap["packet_time_min"], cap["packet_time_max"]), (100.0, 900.0))   # 시작은 첫 패킷 그대로
        self.assertEqual(label_window(600, 300, 100.0, 900.0, "live", 0.8), "live")

    def test_files_without_coverage_keep_packet_rule(self):
        # 덮은 시간을 모르는 파일만 있으면 예전처럼 마지막 패킷 시각. 덮은 시간이 패킷보다 앞이어도 패킷이 이긴다
        self.assertEqual(observed_until(self.files), 699.0)
        self.assertEqual(observed_until([file_row("cc", "x", 400.0, 699.0, covered_to=698.5)]), 699.0)


def rev(n, h="0" * 8):
    return f"rev-{n:04d}-{h}"


class PruneRevisionsTest(unittest.TestCase):
    """리비전 정리: 성공 리비전 최신 keep개와 그보다 새로운 리비전만 남긴다."""

    def test_keeps_latest_done(self):
        revs = [(rev(n), "done") for n in range(1, 6)]
        self.assertEqual(revisions_to_prune(revs, 2), [rev(1), rev(2), rev(3)])     # 오래된 것부터
        self.assertEqual(revisions_to_prune(revs, 5), [])

    def test_last_success_survives_failures(self):
        # 성공 뒤 실패가 이어져도 마지막 성공(에이전트가 읽는 리비전)과 그 뒤 실패들은 남는다
        revs = [(rev(1), "done"), (rev(2), "done"), (rev(3), "failed"), (rev(4), "running")]
        self.assertEqual(revisions_to_prune(revs, 1), [rev(1)])

    def test_old_failed_or_broken_pruned(self):
        # 최신 성공보다 오래된 실패·중단(pipeline.json 없음)은 지운다. 성공이 하나도 없으면 아무것도 지우지 않는다
        revs = [(rev(1), "failed"), (rev(2), None), (rev(3), "done")]
        self.assertEqual(revisions_to_prune(revs, 2), [rev(1), rev(2)])
        self.assertEqual(revisions_to_prune([(rev(1), "failed"), (rev(2), None)], 1), [])

    def test_order_by_file_count_not_text(self):
        # 이름의 파일 수가 네 자리를 넘어도 숫자로 비교한다
        revs = [(rev(9999), "done"), (rev(10000), "done")]
        self.assertEqual(revisions_to_prune(revs, 1), [rev(9999)])
        with self.assertRaises(ValueError):
            revisions_to_prune(revs, 0)

    def test_prune_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            cap = Path(tmp)
            for n, status in [(1, "done"), (2, "done"), (3, "done")]:
                d = cap / rev(n)
                (d / "graphs").mkdir(parents=True)
                (d / "graphs" / "edges.parquet").write_bytes(b"x" * 100)
                (d / "pipeline.json").write_text(json.dumps({"status": status, "job_id": 20 + n, "steps": []}))
            (cap / "rev-notes").mkdir()                     # 리비전 이름이 아닌 폴더는 건드리지 않는다
            planned = prune_revisions(cap, 2, dry_run=True)
            self.assertEqual([(p["revision"], p["job_id"]) for p in planned], [(rev(1), 21)])
            self.assertTrue((cap / rev(1)).exists())        # dry-run은 지우지 않는다
            self.assertFalse((cap / PRUNE_LOG).exists())

            done = prune_revisions(cap, 2)
            self.assertEqual(done, planned)
            self.assertGreaterEqual(done[0]["bytes"], 100)
            self.assertEqual(sorted(d.name for d in cap.iterdir()), [PRUNE_LOG, rev(2), rev(3), "rev-notes"])
            line = json.loads((cap / PRUNE_LOG).read_text().splitlines()[0])
            self.assertEqual((line["revision"], line["job_id"], line["pipeline"]["status"]), (rev(1), 21, "done"))
            self.assertEqual(prune_revisions(cap, 2), [])    # 다시 불러도 그대로


if __name__ == "__main__":
    unittest.main()
