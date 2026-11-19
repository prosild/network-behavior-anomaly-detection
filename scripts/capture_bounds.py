"""capinfos로 원본 PCAP마다 패킷 시각의 최솟값·최댓값을 재고 manifest로 남긴다."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = PROJECT_ROOT / "configs" / "captures.cic-ids-2017.v1.json"
DEFAULT_OUT = PROJECT_ROOT / "manifests" / "cic-ids-2017.capture-bounds.v1.json"
INPUT_ROOT = PROJECT_ROOT / "CIC-IDS-2017"
INPUT_MANIFEST = PROJECT_ROOT / "manifests" / "cic-ids-2017.inputs.v1.json"


def capinfos_bounds(pcap):
    # -a/-e: 가장 이른·늦은 패킷 시각, -S: epoch 초, -T -r: 머리글 없는 탭 구분 한 줄.
    # 파일 순서상 첫·마지막 패킷이 아니라 시각의 최솟값·최댓값이다(설계 4.3절).
    out = subprocess.run(["capinfos", "-a", "-e", "-S", "-T", "-r", str(pcap)],
                         check=True, capture_output=True, text=True).stdout
    _, start, end = out.rstrip("\n").split("\t")
    return start, end


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    if args.out.exists():
        sys.exit(f"이미 있다: {args.out}")

    config = json.loads(args.config.read_text(encoding="utf-8"))
    known = {f["path"]: f for f in json.loads(INPUT_MANIFEST.read_text(encoding="utf-8"))["files"]}
    version = subprocess.run(["capinfos", "--version"], check=True, capture_output=True,
                             text=True).stdout.splitlines()[0]

    captures = []
    for c in config["captures"]:
        entry = known[c["pcap"]]
        pcap = INPUT_ROOT / c["pcap"]
        # 입력 manifest의 해시를 쓴다. 크기가 다르면 다른 파일이므로 멈춘다.
        if pcap.stat().st_size != entry["size_bytes"]:
            sys.exit(f"크기가 입력 manifest와 다르다: {c['pcap']}")
        start, end = capinfos_bounds(pcap)
        print(f"{c['capture_id']}: {start} ~ {end}")
        # 원래 자릿수를 잃지 않도록 문자열로 남긴다. 계산할 때 float로 바꾼다.
        captures.append({"capture_id": c["capture_id"], "pcap": c["pcap"],
                         "pcap_sha256": entry["sha256"], "packet_time_min": start,
                         "packet_time_max": end})

    manifest = {
        "manifest_id": args.out.stem,
        "schema_version": 1,
        "config_id": config["config_id"],
        "tool": version,
        "command": "capinfos -a -e -S -T -r <pcap>",
        "meaning": "패킷 시각의 최솟값·최댓값(epoch 초, UTC). 파일 순서상 첫·마지막 패킷과 다를 수 있다.",
        "captures": captures,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    tmp = args.out.with_name(args.out.name + ".tmp")
    tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, args.out)
    print(f"manifest={args.out.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
