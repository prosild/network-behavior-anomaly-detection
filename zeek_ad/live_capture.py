"""실습망 캡처(lab-YYYYMMDD) 다시 계산 준비(DD-012): 그날 받은 파일 목록 → 리비전 → Zeek 합치기 → 캡처 설정·경계.

기존 배치 스크립트(Silver·Gold·이벤트·그래프)는 "캡처 하나 = Zeek 실행 폴더 하나 + 캡처 설정 + 캡처 경계"를 입력으로 받는다.
실습망은 파일(예: 5분)마다 Zeek를 따로 돌리므로, 그날 파일들의 Zeek 로그를 한 폴더로 합치고 나머지 둘을 만들어 넘긴다.

리비전: 그날 지금까지 받은 파일 묶음 하나. 이름은 rev-<파일 수>-<파일 해시 묶음의 해시 앞 8자리>다.
같은 파일 묶음이면 이름이 같고, 파일이 하나 늘면 새 리비전 폴더에 처음부터 다시 쓴다.
이전 리비전은 다시 계산이 성공한 뒤 정리한다(prune_revisions). 결과는 DB에 남고, 폴더는 최신 몇 개만 둔다.
표준 라이브러리만 쓴다(시험을 Spark 없이 돌린다).
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil

from zeek_ad.provenance import PROJECT_ROOT, file_record, project_path, sha256

# 실행마다 내용이 달라 합치지 않는 로그(설정 run.v2의 nondeterministic_logs와 같다)
SKIP_LOGS = {"packet_filter.log"}
# Zeek 연결·파일 식별자가 들어가는 필드. 문자열 하나이거나 목록이다(조사: Zeek 8 run-02 로그 전체).
ID_FIELDS = {"uid", "fuid", "id", "uids", "conn_uids", "orig_fuids", "resp_fuids", "parent_fuid",
             "cert_chain_fuids", "client_cert_chain_fuids"}
LIVE_USAGE = "live"


def day_files(conn, capture_id):
    """그날 Zeek까지 끝난 파일들. 첫 패킷 시각 순서다(같으면 해시 순서).

    covered_to: 수집기가 이 파일로 관측을 마친 시각(DD-016). 이름에 덮은 시간이 없던 파일은 None.
    """
    rows = conn.execute("""SELECT file_sha256, file_name, zeek_run_dir, packets,
                                  extract(epoch FROM first_packet_at), extract(epoch FROM last_packet_at),
                                  extract(epoch FROM covered_to)
                           FROM zeekad.ingest_file
                           WHERE capture_id = %s AND status IN ('zeek_done', 'pipeline_done')
                           ORDER BY first_packet_at, file_sha256""", (capture_id,)).fetchall()
    return [{"sha256": r[0].strip(), "name": r[1], "zeek_run_dir": r[2], "packets": int(r[3]),
             "first": float(r[4]), "last": float(r[5]), "covered_to": None if r[6] is None else float(r[6])}
            for r in rows]


def files_sha256(files):
    """파일 해시 묶음의 해시(순서 무관). 리비전 이름과 캡처 경계의 pcap_sha256에 쓴다."""
    return hashlib.sha256("\n".join(sorted(f["sha256"] for f in files)).encode()).hexdigest()


def revision_id(files):
    return f"rev-{len(files):04d}-{files_sha256(files)[:8]}"


def uid_tag(file_sha256):
    return "-" + file_sha256[:6]


def tag_ids(record, tag):
    """식별자 필드 뒤에 파일 표시를 붙인다. 다른 필드는 그대로 둔다."""
    for key in ID_FIELDS & record.keys():
        v = record[key]
        if isinstance(v, str):
            record[key] = v + tag
        elif isinstance(v, list):
            record[key] = [x + tag if isinstance(x, str) else x for x in v]
    return record


def merge_zeek(files, out_dir):
    """파일별 Zeek 출력의 같은 이름 로그를 첫 패킷 순서로 이어 붙인다. run-manifest.json도 Silver가 읽는 형식으로 쓴다.

    한 파일 안의 행 순서(Zeek가 쓴 순서)는 그대로 둔다. 모든 파일이 같은 Zeek 설정·이미지로 처리됐는지 확인한다.
    uid가 겹치지 않게 한다: Zeek seed를 고정했으므로(재현성, 단계 1) 파일마다 같은 uid 순서가 나온다. 그대로 합치면
    다른 파일의 DNS·HTTP 기록이 엉뚱한 연결에 uid로 붙는다. 그래서 식별자 필드 뒤에 "-<파일 해시 6자리>"를 붙인다.
    원래 파일의 uid는 이 꼬리를 떼면 된다(파일별 Zeek 출력은 고치지 않는다).
    임시 폴더에 다 쓴 뒤 이름을 바꾼다. 그래서 out_dir이 있으면 완성된 결과다.
    """
    out_dir = Path(out_dir)
    if out_dir.exists():
        raise FileExistsError(f"이미 있다: {project_path(out_dir)}")
    runs = [PROJECT_ROOT / f["zeek_run_dir"] for f in files]
    manifests = [json.loads((r / "run-manifest.json").read_text(encoding="utf-8")) for r in runs]
    same = {(m["config"]["sha256"], m["image"]) for m in manifests}
    if len(same) != 1:
        raise ValueError(f"Zeek 설정·이미지가 다른 파일이 섞였다: {sorted(same)}")

    tmp = out_dir.with_name(out_dir.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    names = sorted({p.name for r in runs for p in r.glob("*.log")} - SKIP_LOGS)
    outputs = []
    for name in names:
        rows = 0
        with open(tmp / name, "w", encoding="utf-8") as dst:
            for f, r in zip(files, runs):
                src = r / name
                if not src.exists():
                    continue
                tag = uid_tag(f["sha256"])
                with open(src, encoding="utf-8") as fh:
                    for line in fh:
                        if not line.strip():
                            continue
                        record = tag_ids(json.loads(line), tag)
                        dst.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
                        rows += 1
        outputs.append({"name": name, "rows": rows, "size_bytes": (tmp / name).stat().st_size,
                        "sha256": sha256(tmp / name), "deterministic": True})

    first = manifests[0]
    manifest = {
        "run_manifest_version": 1,
        "merged": {"note": "파일별 Zeek 출력을 첫 패킷 순서로 이어 붙였다(DD-012). 파일 경계에 걸친 연결은 둘로 잘려 있다. "
                           "식별자 필드(uid·fuid 등) 뒤에 '-<파일 해시 6자리>'를 붙여 파일 사이 uid 겹침을 없앴다.",
                   "id_fields": sorted(ID_FIELDS),
                   "sources": [{"file_sha256": f["sha256"], "file_name": f["name"],
                                "run_manifest": file_record(r / "run-manifest.json")}
                               for f, r in zip(files, runs)]},
        "config": first["config"], "image": first["image"], "zeek_version": first["zeek_version"],
        "scripts": first["scripts"], "seed_file": first["seed_file"],
        "outputs": outputs,
    }
    (tmp / "run-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, out_dir)
    return manifest


def observed_until(files):
    """그날 관측이 확실한 마지막 시각: 마지막 패킷 시각과 파일이 덮은 시간의 끝 중 늦은 쪽(DD-016).

    공격이 09:49:49에 끝나고 그 파일이 09:50:00까지 덮었다면 09:45~09:50 창은 다 관측한 창이다.
    덮은 시간을 모르는 파일(이름에 없음)은 패킷 시각만 쓴다(예전 규칙).
    """
    return max(max(f["last"], f.get("covered_to") or f["last"]) for f in files)


def capture_config(capture_id, files, zeek_dir, out_dir):
    """기존 스크립트의 --captures·--bounds에 넘길 두 파일을 쓴다. 반환: (설정 경로, 경계 경로).

    용도는 live다. 학습 캡처가 아니라서 창은 나누지 않고, 캡처 경계에 걸친 창(아직 다 받지 않은 마지막 창 등)은
    capture_edge로 표시되어 채점 큐에서 빠진다(기존 규칙 그대로).
    """
    out_dir = Path(out_dir)
    config = {"config_id": f"captures.{capture_id}.{out_dir.name}", "schema_version": 1, "dataset": "lab (DD-012)",
              "note": "live_capture.capture_config가 그날 받은 파일로 만든 설정이다. 손으로 고치지 않는다.",
              "captures": [{"capture_id": capture_id, "zeek_run_dir": project_path(zeek_dir), "usage": LIVE_USAGE}]}
    bounds = {"manifest_id": f"capture-bounds.{capture_id}.{out_dir.name}", "schema_version": 1,
              "meaning": ("packet_time_min: 그날 첫 패킷 시각. packet_time_max: 마지막 패킷 시각과 수집기가 관측을 마친 시각"
                          "(covered_to, DD-016) 중 늦은 쪽(epoch 초, UTC). 값은 처리 기록(ingest_file)에서 읽는다."),
              "captures": [{"capture_id": capture_id, "files": len(files),
                            # 채점 결과에 남는 "입력 캡처 해시" 자리. PCAP이 여러 개라 파일 해시 묶음의 해시를 쓴다.
                            "pcap_sha256": files_sha256(files),
                            "packet_time_min": f"{min(f['first'] for f in files):.6f}",
                            "packet_time_max": f"{observed_until(files):.6f}"}]}
    paths = out_dir / "captures.json", out_dir / "capture-bounds.json"
    if all(p.exists() for p in paths):
        return paths            # 이미 만든 리비전: 다시 쓰지 않는다(Gold manifest가 이 파일 해시를 기록한다)
    for path, body in zip(paths, (config, bounds)):
        path.write_text(json.dumps(body, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return paths


# 리비전 정리(DD-015 "배포 전에 할 일"). 리비전 하나는 약 84MB이고 대부분이 그래프다(월요일 그래프 전체를 다시 쓴다).
REVISION_NAME = re.compile(r"^rev-(\d+)-[0-9a-f]{8}$")
PRUNE_LOG = "pruned.jsonl"


def revision_record(rev_dir):
    """리비전의 처리 기록(pipeline.json). 없거나 읽지 못하면 빈 dict(계산이 중간에 끊긴 폴더)."""
    try:
        return json.loads((Path(rev_dir) / "pipeline.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def revisions_to_prune(revisions, keep):
    """지울 리비전 이름 목록(오래된 것부터). revisions: [(이름, 상태)], 상태는 pipeline.json의 status(없으면 None).

    새것의 기준은 이름의 파일 수다. 그날 파일은 늘기만 하므로 파일이 많은 리비전이 나중 계산이다.
    남기는 것:
    - 성공(done) 리비전 중 최신 keep개. 에이전트는 최신 성공 작업의 리비전(Gold 위치)을 읽는다.
    - 가장 최신 성공 리비전보다 새로운 리비전 전부(계산 중이거나 실패 원인을 볼 것). 실패가 이어져도
      마지막 성공 리비전은 지워지지 않는다.
    지우는 것: 나머지(오래된 성공, 최신 성공보다 오래된 실패·중단). 성공 리비전이 없으면 아무것도 지우지 않는다.
    """
    if keep < 1:
        raise ValueError("keep은 1 이상이어야 한다(최신 성공 리비전은 에이전트가 읽는다)")
    ordered = sorted(revisions, key=lambda r: (int(REVISION_NAME.match(r[0]).group(1)), r[0]), reverse=True)
    done = [k for k, (_, status) in enumerate(ordered) if status == "done"]
    if not done:
        return []
    kept = set(done[:keep]) | set(range(done[0]))
    return [name for k, (name, _) in reversed(list(enumerate(ordered))) if k not in kept]


def folder_bytes(path):
    """폴더 안 파일 크기 합(심볼릭 링크는 따라가지 않는다)."""
    total = 0
    for root, _, names in os.walk(path):
        for name in names:
            total += os.lstat(os.path.join(root, name)).st_size
    return total


def prune_revisions(capture_dir, keep, dry_run=False):
    """<runs_out>/<캡처 ID> 폴더에서 오래된 리비전 폴더를 지운다. 반환: 지운(dry_run이면 지울) 리비전 목록.

    리비전 이름 형식의 폴더만 본다(다른 파일·폴더는 건드리지 않는다). 지운 리비전의 처리 기록(단계별 시간·
    채점 작업 번호)은 같은 폴더의 pruned.jsonl에 한 줄씩 남긴다. 결과(점수·사건·보고서)는 DB에 그대로 있다.
    """
    capture_dir = Path(capture_dir)
    found = {d.name: d for d in capture_dir.iterdir()
             if d.is_dir() and not d.is_symlink() and REVISION_NAME.match(d.name)}
    records = {name: revision_record(d) for name, d in found.items()}
    names = revisions_to_prune([(name, records[name].get("status")) for name in found], keep)
    out = []
    for name in names:
        record = records[name]
        entry = {"revision": name, "status": record.get("status"), "job_id": record.get("job_id"),
                 "bytes": folder_bytes(found[name])}
        if not dry_run:
            shutil.rmtree(found[name])
            line = {**entry, "pruned_at_utc": datetime.now(timezone.utc).isoformat(), "pipeline": record}
            with (capture_dir / PRUNE_LOG).open("a", encoding="utf-8") as f:
                f.write(json.dumps(line, ensure_ascii=False) + "\n")
        out.append(entry)
    return out
