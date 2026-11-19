"""수신 처리(zeek_ad.ingest) 시험. 표준 라이브러리만 쓴다(DB·capinfos·Zeek 대신 가짜를 쓴다).

실행: python3 -m unittest tests.test_ingest -v
끊긴 처리 이어 하기(InterruptedTest, 프로젝트 검토 Q57 결함 3):
- 옮기기 전에 끊겨 수신 폴더에 남은 파일은 중복으로 치우지 않고 이어서 처리한다.
- 옮긴 뒤 끊겨 저장 폴더에 있는 파일은 recover_stale이 Zeek를 돌린다.
- Zeek 출력 폴더가 이미 있으면(Zeek는 끝났는데 상태를 못 씀) Zeek를 다시 돌리지 않고 완료로 기록한다.
- 이미 끝난 파일을 다시 넣으면 예전처럼 중복으로 치운다.
"""

import hashlib
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest import mock

from zeek_ad import ingest
from zeek_ad.ingest import capture_id_for, checked_coverage, coverage_from_name, ready_files


class ReadyFilesTest(unittest.TestCase):
    def test_skips_fresh_and_unmatched_files_and_sorts(self):
        with tempfile.TemporaryDirectory() as d:
            now = time.time()
            for name, age in [("b.pcap", 60), ("a.pcap", 60), ("c.pcapng", 120), ("fresh.pcap", 2), ("x.txt", 60)]:
                p = Path(d, name)
                p.write_bytes(b"x")
                os.utime(p, (now - age, now - age))
            got = [p.name for p in ready_files(d, ["*.pcap", "*.pcapng"], 10, now=now)]
            # 오래된 것부터, 같은 시각이면 이름순. 쓰는 중일 수 있는 fresh와 패턴 밖 x.txt는 뺀다
            self.assertEqual(got, ["c.pcapng", "a.pcap", "b.pcap"])


class CaptureIdTest(unittest.TestCase):
    def test_utc_date_of_first_packet(self):
        self.assertEqual(capture_id_for(1796086800.0, "lab"), "lab-20261201")       # 2026-12-01 01:00 UTC
        self.assertEqual(capture_id_for(1796083199.9, "lab"), "lab-20261130")       # 하루 전 23:59:59 UTC


class CoverageNameTest(unittest.TestCase):
    """수집기가 이름에 넣은 덮은 시간(DD-016)."""
    NAME = "lab-20261118T094500Z-20261118T095000Z.pcap"

    def test_reads_start_and_end_utc(self):
        self.assertEqual(coverage_from_name(self.NAME), (1794995100.0, 1794995400.0))    # 09:45:00~09:50:00 UTC

    def test_other_names_have_no_coverage(self):
        for name in ["lab-20261118-094556.pcap", "lab-0100-again.pcap",
                     "lab-20261118T095000Z-20261118T094500Z.pcap"]:                   # 끝이 시작보다 앞
            self.assertIsNone(coverage_from_name(name), name)

    def test_coverage_must_contain_packets(self):
        # 패킷이 덮은 시간 안(1초 여유)에 있어야 믿는다. 밖이면 이름을 손으로 바꾼 것으로 보고 쓰지 않는다
        self.assertEqual(checked_coverage(self.NAME, 1794995369.5, 1794995389.1), (1794995100.0, 1794995400.0))
        self.assertIsNotNone(checked_coverage(self.NAME, 1794995099.5, 1794995400.9))
        self.assertIsNone(checked_coverage(self.NAME, 1794995000.0, 1794995389.1))
        self.assertIsNone(checked_coverage(self.NAME, 1794995369.5, 1794995500.0))



class FakeIngestDB:
    """ingest가 쓰는 SQL 네 가지만 흉내 낸다. rows: {sha256: {열: 값}}."""

    def __init__(self):
        self.rows = {}

    def commit(self):
        pass

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        result = mock.Mock()
        if sql.startswith("SELECT status FROM ingest_file"):
            row = self.rows.get(params[0])
            result.fetchone.return_value = (row["status"],) if row else None
        elif sql.startswith("INSERT INTO ingest_file"):
            self.rows[params[0]] = {"file_name": params[1], "status": "received", "capture_id": None,
                                    "packets": None}
        elif sql.startswith("UPDATE ingest_file SET"):
            cols = re.findall(r"(\w+) = %s", sql.split(" WHERE ")[0])
            self.rows[params[-1]].update(dict(zip(cols, params[:-1])))
        elif "WHERE status = 'received' AND capture_id IS NOT NULL" in sql:
            result.fetchall.return_value = [(k, r["file_name"], r["capture_id"], r["packets"])
                                            for k, r in self.rows.items()
                                            if r["status"] == "received" and r["capture_id"]]
        else:
            raise AssertionError(sql)
        return result


class InterruptedTest(unittest.TestCase):
    CONFIG = {"store": "store", "zeek_out": "zeek", "zeek_config": "zeek.json", "capture_id_prefix": "lab"}
    FIRST = 1794995100.0                         # 2026-11-18 09:45 UTC → lab-20261118

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.inbox = self.root / "inbox"
        self.inbox.mkdir()
        self.db = FakeIngestDB()
        self.zeek = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr=""))
        for target, value in [("PROJECT_ROOT", self.root), ("capinfos", lambda p: (3, self.FIRST, self.FIRST + 5)),
                              ("subprocess.run", self.zeek)]:
            patcher = mock.patch(f"zeek_ad.ingest.{target}", value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def pcap(self, name="lab-a.pcap", body=b"pcap-bytes"):
        path = self.inbox / name
        path.write_bytes(body)
        return path, hashlib.sha256(body).hexdigest()

    def stored(self, name="lab-a.pcap"):
        return self.root / "store" / "lab-20261118" / name

    def test_cut_before_move_resumes_instead_of_duplicate(self):
        path, digest = self.pcap()
        self.db.rows[digest] = {"file_name": path.name, "status": "received", "capture_id": None, "packets": None}
        self.assertEqual(ingest.ingest_one(self.db, path, self.CONFIG, log=lambda *a: None), "zeek_done")
        self.assertTrue(self.stored().exists())
        self.assertFalse((self.root / "store" / "_duplicates").exists())
        self.assertEqual(self.db.rows[digest]["status"], "zeek_done")

    def test_cut_after_move_is_recovered(self):
        path, digest = self.pcap()
        self.db.rows[digest] = {"file_name": path.name, "status": "received", "capture_id": "lab-20261118",
                                "packets": 3}
        self.stored().parent.mkdir(parents=True)
        path.rename(self.stored())
        self.assertEqual(ingest.recover_stale(self.db, self.CONFIG, 600, log=lambda *a: None), (1, 0))
        self.assertEqual(self.db.rows[digest]["status"], "zeek_done")
        self.zeek.assert_called_once()

    def test_existing_zeek_output_is_taken_as_done(self):
        path, digest = self.pcap()
        self.db.rows[digest] = {"file_name": path.name, "status": "received", "capture_id": "lab-20261118",
                                "packets": 3}
        self.stored().parent.mkdir(parents=True)
        path.rename(self.stored())
        (self.root / "zeek" / "lab-20261118" / f"lab-a-{digest[:8]}").mkdir(parents=True)
        self.assertEqual(ingest.recover_stale(self.db, self.CONFIG, 600, log=lambda *a: None), (1, 0))
        self.assertEqual(self.db.rows[digest]["status"], "zeek_done")
        self.zeek.assert_not_called()                 # 다시 돌리면 run_zeek.py가 "출력 폴더가 있다"로 거부한다

    def test_recover_skips_file_still_in_inbox(self):
        path, digest = self.pcap()
        self.db.rows[digest] = {"file_name": path.name, "status": "received", "capture_id": "lab-20261118",
                                "packets": 3}
        self.assertEqual(ingest.recover_stale(self.db, self.CONFIG, 600, log=lambda *a: None), (0, 0))
        self.assertEqual(self.db.rows[digest]["status"], "received")   # 수신 폴더 쪽은 ingest_one이 이어서 한다

    def test_capture_id_recorded_before_move(self):
        path, digest = self.pcap()
        seen = {}

        def move(src, dst):
            seen["capture_id"] = self.db.rows[digest]["capture_id"]
            os.rename(src, dst)
        with mock.patch("zeek_ad.ingest.shutil.move", move):
            ingest.ingest_one(self.db, path, self.CONFIG, log=lambda *a: None)
        self.assertEqual(seen["capture_id"], "lab-20261118")

    def test_done_file_is_still_duplicate(self):
        path, digest = self.pcap()
        self.db.rows[digest] = {"file_name": path.name, "status": "zeek_done", "capture_id": "lab-20261118",
                                "packets": 3}
        self.assertEqual(ingest.ingest_one(self.db, path, self.CONFIG, log=lambda *a: None), "duplicate")
        self.assertTrue((self.root / "store" / "_duplicates" / f"{path.name}.{digest[:8]}").exists())


if __name__ == "__main__":
    unittest.main()
