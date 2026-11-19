"""수신 폴더의 새 PCAP을 받아 저장하고 Zeek를 돌린다(DD-012 파일 단위 자동 파이프라인의 입구).

파일 하나의 흐름:
1. 수신 폴더(inbox)에서 일정 시간(min_age_seconds) 동안 바뀌지 않은 파일만 고른다.
   계약은 "다 쓴 파일만 원자적으로 옮겨 넣는다"이고, 이 대기는 실수로 쓰는 중인 파일을 넣었을 때의 보조 장치다.
2. sha256을 계산한다. 처리 기록(ingest_file)에 같은 해시가 있으면 이미 받은 파일이라 수신 폴더에서만 치운다.
   단, 그 기록이 received면 지난번 처리가 중간에 끊긴 것이다(컨테이너 재시작 등). 중복이 아니라 이어서 처리한다.
3. capinfos로 패킷 수와 첫·마지막 패킷 시각을 잰다. 첫 패킷의 UTC 날짜로 캡처 ID(lab-YYYYMMDD)를 정한다.
   수집기(scripts/capture_rotate.sh)가 만든 이름(lab-<시작>-<끝>.pcap)이면 파일이 덮은 시간도 남긴다(DD-016).
   이 값들은 파일을 옮기기 전에 기록한다. 옮긴 뒤 끊겨도 저장 폴더에서 파일을 찾을 수 있게 하려는 것이다.
4. 파일을 저장 폴더(store/<캡처 ID>/)로 옮긴다. Zeek 실행 기록은 옮긴 뒤의 경로를 가리킨다.
5. scripts/run_zeek.py로 Zeek를 돌린다(출력: <zeek_out>/<캡처 ID>/<파일 이름>-<해시 앞 8자리>/).
   출력 폴더가 이미 있으면 앞선 실행이 Zeek를 마치고 상태를 쓰기 전에 끊긴 것이라 완료로 기록한다
   (run_zeek.py는 임시 폴더에 다 쓴 뒤 이름을 바꿔 게시하므로, 있는 폴더는 완성본이다).
각 단계 결과를 ingest_file의 status(received → zeek_done 또는 failed)로 남긴다.
옮긴 뒤 끊겨 received로 남은 파일은 감시 프로그램이 recover_stale로 이어서 처리한다(프로젝트 검토 Q57 결함 3).
"""

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from zeek_ad.provenance import PROJECT_ROOT


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rel(path):
    return Path(path).resolve().relative_to(PROJECT_ROOT).as_posix()


def ready_files(inbox, patterns, min_age_seconds, now=None):
    """처리할 파일: 패턴에 맞고, 마지막 수정 뒤 min_age_seconds가 지난 파일. 오래된 것부터."""
    now = time.time() if now is None else now
    found = {p for pattern in patterns for p in Path(inbox).glob(pattern) if p.is_file()}
    return sorted((p for p in found if now - p.stat().st_mtime >= min_age_seconds), key=lambda p: (p.stat().st_mtime, p.name))


def capinfos(path):
    """(패킷 수, 첫 패킷 epoch, 마지막 패킷 epoch). 패킷이 없으면 시각은 None."""
    out = subprocess.run(["capinfos", "-T", "-r", "-c", "-a", "-e", "-S", str(path)],
                         capture_output=True, text=True, check=True).stdout.strip()
    _, packets, first, last = out.rsplit("\t", 3)
    to_float = lambda s: None if s in ("", "n/a") else float(s)  # noqa: E731
    return int(packets), to_float(first), to_float(last)


COVERAGE_NAME = re.compile(r"(\d{8}T\d{6}Z)-(\d{8}T\d{6}Z)")


def coverage_from_name(name):
    """수집기가 이름에 넣은 덮은 시간(시작, 끝 epoch 초). 그런 이름이 아니면 None.

    예: lab-20261118T094500Z-20261118T095000Z.pcap → (1794995100.0, 1794995400.0)
    """
    m = COVERAGE_NAME.search(name)
    if not m:
        return None
    start, end = (datetime.strptime(x, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp() for x in m.groups())
    return (start, end) if end > start else None


def checked_coverage(name, first, last, slack=1.0):
    """이름의 덮은 시간이 패킷 시각과 맞을 때만 돌려준다. 맞지 않으면(손으로 바꾼 이름 등) None.

    시작·끝은 초 아래를 버린 값이라 1초 여유(slack)를 둔다.
    """
    cov = coverage_from_name(name)
    if cov is None or not (cov[0] - slack <= first and last <= cov[1] + slack):
        return None
    return cov


def capture_id_for(first_epoch, prefix):
    return f"{prefix}-{datetime.fromtimestamp(first_epoch, timezone.utc):%Y%m%d}"


def utc(epoch):
    return None if epoch is None else datetime.fromtimestamp(epoch, timezone.utc)


def _set(conn, digest, **fields):
    cols = ", ".join(f"{k} = %s" for k in fields)
    conn.execute(f"UPDATE ingest_file SET {cols}, updated_at = now() WHERE file_sha256 = %s",
                 (*fields.values(), digest))
    conn.commit()


def ingest_one(conn, path, config, log=print):
    """파일 하나를 처리한다. 반환: 처리 기록의 최종 status(이미 받은 파일이면 'duplicate')."""
    path = Path(path)
    digest = sha256(path)
    store_root = PROJECT_ROOT / config["store"]
    known = conn.execute("SELECT status FROM ingest_file WHERE file_sha256 = %s", (digest,)).fetchone()
    if known and known[0] != "received":
        dup = store_root / "_duplicates"
        dup.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), dup / f"{path.name}.{digest[:8]}")
        log(f"{path.name}: 이미 받은 파일(같은 해시). 수신 폴더에서 치웠다")
        return "duplicate"

    if known:
        log(f"{path.name}: 지난번 처리가 중간에 끊긴 파일(received). 이어서 처리한다")
    else:
        conn.execute("""INSERT INTO ingest_file (file_sha256, file_name, size_bytes, status)
                        VALUES (%s, %s, %s, 'received')""", (digest, path.name, path.stat().st_size))
        conn.commit()
    try:
        packets, first, last = capinfos(path)
        if first is None:
            raise ValueError("패킷이 없는 파일")
        capture_id = capture_id_for(first, config["capture_id_prefix"])
        stored = store_root / capture_id / path.name
        if stored.exists():  # 이름이 같고 내용이 다른 파일
            stored = stored.with_name(f"{path.stem}-{digest[:8]}{path.suffix}")
        cov_from, cov_to = checked_coverage(path.name, first, last) or (None, None)
        # 옮기기 전에 기록한다: 옮긴 뒤 끊기면 recover_stale이 capture_id로 저장 폴더에서 찾는다
        _set(conn, digest, packets=packets, first_packet_at=utc(first), last_packet_at=utc(last),
             capture_id=capture_id, covered_from=utc(cov_from), covered_to=utc(cov_to))
        stored.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), stored)

        return run_zeek(conn, digest, stored, capture_id, packets, config, log)
    except Exception as e:  # 오류 문장은 짧게 남긴다. 파일은 저장 폴더나 수신 폴더에 그대로 있다
        _set(conn, digest, status="failed", error=f"{type(e).__name__}: {str(e)[:200]}")
        log(f"{path.name}: 실패 {type(e).__name__}: {e}")
        return "failed"


def run_zeek(conn, digest, stored, capture_id, packets, config, log=print):
    """저장 폴더의 파일 하나에 Zeek를 돌리고 처리 기록을 zeek_done으로 바꾼다. 실패하면 예외를 던진다."""
    run_dir = PROJECT_ROOT / config["zeek_out"] / capture_id / f"{stored.stem}-{digest[:8]}"
    if run_dir.exists():
        # 앞선 실행이 Zeek를 마치고 상태를 쓰기 전에 끊겼다. 게시된 폴더는 완성본이다(run_zeek.py는 덮어쓰기를 거부한다)
        _set(conn, digest, zeek_run_dir=rel(run_dir), status="zeek_done", error=None)
        log(f"{stored.name}: Zeek 결과가 이미 있다(앞선 실행이 끊김). 완료로 기록 → {rel(run_dir)}")
        return "zeek_done"
    result = subprocess.run([sys.executable, str(PROJECT_ROOT / "scripts" / "run_zeek.py"),
                             "--pcap", str(stored), "--out", str(run_dir),
                             "--config", str(PROJECT_ROOT / config["zeek_config"])],
                            capture_output=True, text=True)
    if result.returncode != 0:
        last = (result.stdout + result.stderr).strip().splitlines()[-1:] or [""]
        raise RuntimeError(f"Zeek 실패(종료 코드 {result.returncode}): {last[0][:150]}")
    _set(conn, digest, zeek_run_dir=rel(run_dir), status="zeek_done", error=None)
    log(f"{stored.name}: {capture_id}, 패킷 {packets}, Zeek 완료 → {rel(run_dir)}")
    return "zeek_done"


def stored_path(config, capture_id, file_name, digest):
    """ingest_one이 옮긴 위치. 같은 이름의 다른 파일이 있었으면 이름 뒤에 해시 8자리가 붙었다."""
    base = PROJECT_ROOT / config["store"] / capture_id / file_name
    for p in (base, base.with_name(f"{base.stem}-{digest[:8]}{base.suffix}")):
        if p.exists() and sha256(p) == digest:
            return p
    return None


def recover_stale(conn, config, min_age_seconds, log=print):
    """저장 폴더로 옮긴 뒤 처리가 끊겨 received로 남은 파일을 이어서 처리한다. 반환: (성공 수, 실패 수).

    min_age_seconds: 마지막 갱신 뒤 이만큼 지난 기록만 본다. 다른 프로세스(손으로 돌린 --once 등)가 지금 처리 중인
    파일을 건드리지 않으려는 여유다. 수신 폴더에 남은 파일(옮기기 전에 끊김)은 ingest_one이 이어서 하므로 여기서는 뺀다.
    """
    rows = conn.execute("""SELECT file_sha256, file_name, capture_id, packets FROM ingest_file
                           WHERE status = 'received' AND capture_id IS NOT NULL
                             AND updated_at < now() - make_interval(secs => %s)
                           ORDER BY first_packet_at""", (min_age_seconds,)).fetchall()
    ok = bad = 0
    for digest, name, capture_id, packets in rows:
        digest = digest.strip()
        stored = stored_path(config, capture_id, name, digest)
        if stored is None:
            continue                       # 아직 수신 폴더에 있다(ingest_one이 이어서 한다)
        log(f"{name}: 처리가 끊긴 채 received로 남아 있었다. 이어서 Zeek를 돌린다")
        try:
            run_zeek(conn, digest, stored, capture_id, packets, config, log)
            ok += 1
        except Exception as e:
            _set(conn, digest, status="failed", error=f"{type(e).__name__}: {str(e)[:200]}")
            log(f"{name}: 실패 {type(e).__name__}: {e}")
            bad += 1
    return ok, bad


def retry_failed(conn, config, log=print):
    """Zeek 단계에서 실패한 파일(저장 폴더로 옮겨진 파일)을 다시 처리한다. 반환: (성공 수, 실패 수).

    capinfos 전에 실패한 파일(패킷이 없는 파일 등)은 capture_id가 없어 다시 하지 않는다. 내용이 고쳐질 일이 없기 때문이다.
    """
    rows = conn.execute("""SELECT file_sha256, file_name, capture_id, packets FROM ingest_file
                           WHERE status = 'failed' AND capture_id IS NOT NULL ORDER BY first_packet_at""").fetchall()
    ok = bad = 0
    for digest, name, capture_id, packets in rows:
        digest = digest.strip()
        stored = stored_path(config, capture_id, name, digest)
        if stored is None:
            log(f"{name}: 저장 폴더에 같은 내용의 파일이 없어 다시 처리하지 못한다")
            bad += 1
            continue
        try:
            run_zeek(conn, digest, stored, capture_id, packets, config, log)
            ok += 1
        except Exception as e:
            _set(conn, digest, status="failed", error=f"{type(e).__name__}: {str(e)[:200]}")
            log(f"{name}: 다시 실패 {type(e).__name__}: {e}")
            bad += 1
    return ok, bad

