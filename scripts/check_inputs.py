"""Check input paths and sizes without reading or changing dataset contents."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-root", type=Path, default=PROJECT_ROOT / "CIC-IDS-2017"
    )
    parser.add_argument(
        "--manifest", type=Path,
        default=PROJECT_ROOT / "manifests" / "cic-ids-2017.inputs.v1.json",
    )
    args = parser.parse_args()
    root = args.input_root.resolve()
    if not root.is_dir():
        parser.error(f"Input directory does not exist: {root}")

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    expected = {entry["path"]: entry for entry in manifest["files"]}
    # stat() reads filesystem metadata, not PCAP/CSV contents.
    actual = {
        path.relative_to(root).as_posix(): path.stat().st_size
        for path in sorted(root.rglob("*")) if path.is_file()
    }
    missing = sorted(expected.keys() - actual.keys())
    unexpected = sorted(actual.keys() - expected.keys())
    size_mismatches = [
        {"path": path, "expected": expected[path]["size_bytes"], "actual": actual[path]}
        for path in sorted(expected.keys() & actual.keys())
        if expected[path]["size_bytes"] != actual[path]
    ]
    passed = not (missing or unexpected or size_mismatches)
    report = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest_id": manifest["manifest_id"],
        "input_root": str(root),
        "status": "passed" if passed else "failed",
        "checks_performed": ["relative_paths", "file_sizes"],
        "sha256_recomputed": False,
        "file_count": len(actual),
        "counts_by_directory": dict(Counter(str(Path(p).parent) for p in actual)),
        "total_bytes": sum(actual.values()),
        "missing": missing,
        "unexpected": unexpected,
        "size_mismatches": size_mismatches,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
