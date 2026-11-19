"""Zeek로 PCAP 하나를 처리하고, 입력·설정·출력을 연결한 실행 manifest를 남긴다."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "zeek" / "run.v1.json"
INPUT_ROOT = PROJECT_ROOT / "CIC-IDS-2017"
INPUT_MANIFEST = PROJECT_ROOT / "manifests" / "cic-ids-2017.inputs.v1.json"


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def project_path(path):
    # 프로젝트 안의 파일은 상대 경로로 남겨 다른 컴퓨터에서도 읽을 수 있게 한다.
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path)


def file_record(path):
    return {"path": project_path(path), "size_bytes": path.stat().st_size, "sha256": sha256(path)}


def pcap_record(path):
    # 원본은 입력 manifest에 검증된 해시가 있다. 크기가 같으면 그 값을 쓰고 10GB를 다시 읽지 않는다.
    # 배포 이미지에는 CIC 원본도 그 manifest도 없다(실습망 파일만 처리한다). 그때는 해시를 직접 계산한다.
    if not INPUT_MANIFEST.exists():
        return {**file_record(path), "sha256_source": "computed"}
    manifest = json.loads(INPUT_MANIFEST.read_text(encoding="utf-8"))
    known = {entry["path"]: entry for entry in manifest["files"]}
    try:
        entry = known.get(path.relative_to(INPUT_ROOT.resolve()).as_posix())
    except ValueError:
        entry = None
    size = path.stat().st_size
    if entry and entry["size_bytes"] == size:
        return {"path": project_path(path), "size_bytes": size, "sha256": entry["sha256"],
                "sha256_source": manifest["manifest_id"]}
    return {**file_record(path), "sha256_source": "computed"}


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()

    config_path = args.config.resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    pcap = args.pcap.resolve()
    out = args.out.resolve()
    if not pcap.is_file():
        parser.error(f"PCAP does not exist: {pcap}")
    # 완료된 결과를 덮어쓰지 않는다. 다시 돌리려면 다른 출력 폴더를 쓴다.
    if out.exists():
        parser.error(f"Output already exists: {out}")

    # 임시 폴더에 완성한 뒤 이름을 바꿔 게시한다. 중간에 실패하면 out은 생기지 않는다(설계 7.2절).
    tmp = out.with_name(out.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)

    scripts_dir = (PROJECT_ROOT / config["scripts_dir"]).resolve()
    # 실행 방식(ZEEKAD_ZEEK_RUNNER): docker(기본, 설정의 이미지로 컨테이너를 띄움) 또는 local(이미 그 이미지 안에서 돌고 있을 때,
    # 배포용 파이프라인 이미지 deploy/pipeline/Dockerfile). local은 설정과 같은 Zeek 버전인지 확인한 뒤 zeek를 바로 부른다.
    runner = os.environ.get("ZEEKAD_ZEEK_RUNNER", "docker")
    if runner == "local":
        version = subprocess.run(["zeek", "--version"], capture_output=True, text=True, check=True).stdout.split()[-1]
        if version != config["zeek_version"]:
            parser.error(f"Zeek version {version} != config {config['zeek_version']}")
        pcap_dir, script_root = str(pcap.parent), str(scripts_dir)
    else:
        pcap_dir, script_root = "/pcap", "/zeek-scripts"
    zeek_args = [
        *config["zeek_options"],
        "--load-seeds", f"{script_root}/{config['seed_file']}",
        "-r", f"{pcap_dir}/{pcap.name}",
        *[f"{script_root}/{name}" for name in config["scripts"]],
    ]
    if runner == "local":
        command = ["zeek", *zeek_args]
    else:
        command = [
            "docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{pcap.parent}:/pcap:ro",
            "-v", f"{scripts_dir}:/zeek-scripts:ro",
            "-v", f"{tmp}:/out", "-w", "/out",
            config["image"], "zeek", *zeek_args,
        ]

    started_at = now_utc()
    # local은 현재 폴더에 로그를 쓰므로 임시 폴더에서 실행한다(docker는 -w /out이 같은 역할)
    result = subprocess.run(command, capture_output=True, text=True, cwd=tmp if runner == "local" else None)
    finished_at = now_utc()
    # Zeek의 경고도 결과의 일부라 파일로 남긴다.
    (tmp / "zeek.stderr.txt").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        print(result.stderr)
        print(f"Zeek failed with exit code {result.returncode}. Partial output kept in {tmp}")
        return result.returncode

    nondeterministic = set(config["nondeterministic_logs"])
    outputs = []
    for log in sorted(tmp.glob("*.log")):
        with open(log, "rb") as f:
            rows = sum(1 for _ in f)
        outputs.append({
            "name": log.name, "rows": rows, "size_bytes": log.stat().st_size,
            "sha256": sha256(log), "deterministic": log.name not in nondeterministic,
        })

    manifest = {
        "run_manifest_version": 1,
        "config": {"config_id": config["config_id"], **file_record(config_path)},
        "image": config["image"],
        "zeek_version": config["zeek_version"],
        "zeek_args": zeek_args,
        "runner": runner,
        "input_pcap": pcap_record(pcap),
        "scripts": [file_record(scripts_dir / name) for name in config["scripts"]],
        "seed_file": file_record(scripts_dir / config["seed_file"]),
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "outputs": outputs,
    }
    (tmp / "run-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    tmp.rename(out)
    conn = next((o for o in outputs if o["name"] == "conn.log"), None)
    print(json.dumps({
        "out": project_path(out),
        "logs": len(outputs),
        "conn_rows": conn and conn["rows"],
        "conn_sha256": conn and conn["sha256"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
