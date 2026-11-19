"""Zeek 실행 폴더 하나의 conn.log를 Silver Parquet로 저장하고, 검증을 통과하면 Silver manifest를 남긴다."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.silver_conn import build_silver_conn  # noqa: E402

# 이 파일들의 해시가 Silver를 만든 코드 버전이다. 하나라도 바뀌면 다른 코드로 만든 결과다.
CODE_FILES = [
    PROJECT_ROOT / "zeek_ad" / "conn_schema.py",
    PROJECT_ROOT / "zeek_ad" / "silver_conn.py",
    PROJECT_ROOT / "scripts" / "build_silver_conn.py",
]


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True, help="예: outputs/zeek/monday/run-01")
    parser.add_argument("--capture-id", required=True, help="예: cic17-mon")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    out = args.out.resolve()
    # manifest가 있는 캡처만 완료된 결과다. 다음 단계(Gold)는 manifest가 없는 폴더를 읽지 않는다.
    manifest_path = out / "_manifests" / f"{args.capture_id}.json"
    if manifest_path.exists():
        sys.exit(f"이미 완료된 캡처다: {project_path(manifest_path)}")

    run_manifest_path = run_dir / "run-manifest.json"
    run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
    # Bronze 행 수는 Zeek 실행 manifest에 이미 있다. 이 값과 Silver·격리 행 수의 합을 대조한다.
    bronze = next(o for o in run_manifest["outputs"] if o["name"] == "conn.log")
    # 실행 manifest의 해시를 실행 ID로 쓴다. Zeek를 다시 돌려 manifest가 바뀌면 ID도 바뀐다.
    processing_run_id = hashlib.sha256(run_manifest_path.read_bytes()).hexdigest()[:16]

    spark = (
        SparkSession.builder.master("local[*]").appName("build-silver-conn")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")

    silver, quarantine = build_silver_conn(
        spark, str(run_dir / "conn.log"), args.capture_id, processing_run_id
    )
    # 캡처마다 capture_id=<값> 폴더에 쓴다. 상위 폴더를 읽으면 Spark가 폴더 이름에서 capture_id 열을 만든다.
    # 그래서 파일 안에는 capture_id를 넣지 않는다. 넣으면 같은 이름의 열이 두 개가 되어 읽기가 실패한다.
    # 이미 있는 캡처 결과는 덮어쓰지 않는다(mode="error").
    dirs = {name: out / name / f"capture_id={args.capture_id}" for name in ["conn", "quarantine"]}
    for name, df in [("conn", silver), ("quarantine", quarantine)]:
        df.drop("capture_id").write.mode("error").parquet(str(dirs[name]))

    # 검증은 메모리의 DataFrame이 아니라 디스크에 저장된 파일을 다시 읽어서 한다.
    written = spark.read.parquet(str(dirs["conn"]))
    held = spark.read.parquet(str(dirs["quarantine"]))
    # Silver와 격리 행의 원본 행 번호를 합치면 1..N이 정확히 한 번씩 나와야 한다(빠짐·중복 없음).
    numbers = written.select("source_row_number").unionByName(held.select("source_row_number"))
    stats = numbers.agg(
        F.count("*").alias("rows"), F.countDistinct("source_row_number").alias("distinct"),
        F.min("source_row_number").alias("min"), F.max("source_row_number").alias("max"),
    ).first()
    counts = {
        "bronze_rows": bronze["rows"],
        "silver_rows": written.count(),
        "quarantine_rows": held.count(),
        "eof_candidate_rows": written.filter("eof_candidate").count(),
    }
    checks = {
        "rows_match_bronze": counts["silver_rows"] + counts["quarantine_rows"] == bronze["rows"],
        "row_numbers_exact_1_to_n": (stats["rows"] == stats["distinct"] == bronze["rows"]
                                     and stats["min"] == 1 and stats["max"] == bronze["rows"]),
    }
    print(f"processing_run_id={processing_run_id}")
    print(json.dumps({"counts": counts, "checks": checks}, ensure_ascii=False, indent=2))

    if not all(checks.values()):
        spark.stop()
        sys.exit(f"검증 실패. manifest를 쓰지 않았다. 확인 후 {project_path(out)}의 이 캡처 폴더를 지우고 다시 실행한다.")

    manifest = {
        "silver_manifest_version": 1,
        "dataset": out.name,
        "capture_id": args.capture_id,
        "processing_run_id": processing_run_id,
        "source": {
            "run_manifest": file_record(run_manifest_path),
            "conn_log": {"path": project_path(run_dir / "conn.log"), "rows": bronze["rows"],
                         "size_bytes": bronze["size_bytes"], "sha256": bronze["sha256"]},
        },
        "code": [file_record(p) for p in CODE_FILES],
        "runtime": {"spark_version": spark.version, "python_version": platform.python_version()},
        "counts": counts,
        "checks": checks,
        "outputs": [file_record(p) for d in dirs.values() for p in sorted(d.glob("*.parquet"))],
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    spark.stop()

    # 임시 파일에 다 쓴 뒤 이름을 바꾼다. 쓰다가 중단돼도 반쪽짜리 manifest가 남지 않는다.
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = manifest_path.with_name(manifest_path.name + ".tmp")
    tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, manifest_path)
    print(f"manifest={project_path(manifest_path)}")


if __name__ == "__main__":
    main()
