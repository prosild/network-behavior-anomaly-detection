"""TGN 이벤트 표: Silver conn 한 행 = 이벤트 하나. run-02 프로토콜 로그를 uid별로 요약해 붙인다(DD-007).

값은 원래 값 그대로 둔다. 인코딩(어휘, 표준화)은 학습 단계에서 월요일 train으로만 적합한다.
run-02 conn이 Silver의 근거(run-01 conn)와 같은 연결인지 uid로 먼저 확인한다.
"""

import argparse
import json
from pathlib import Path
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad import windows  # noqa: E402
from zeek_ad.provenance import file_record, project_path  # noqa: E402
from zeek_ad.role_windows import load_captures, window_labels  # noqa: E402

CAPTURES_CONFIG = PROJECT_ROOT / "configs" / "captures.cic-ids-2017.v1.json"
BOUNDS_MANIFEST = PROJECT_ROOT / "manifests" / "cic-ids-2017.capture-bounds.v1.json"
# URI에서 공격에 흔한 문자. 비율 = 이 문자들이 차지하는 길이 / URI 길이.
URI_SPECIAL = r"['\"<>%;(){}]|--"


def read_log(spark, path, columns):
    # 로그마다 필요한 열만 읽는다. 없는 열(그날 로그에 한 번도 안 나온 필드)은 null로 채운다.
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        # 그날 그 프로토콜이 한 번도 없으면 Zeek가 로그 파일을 만들지 않는다(실습망 캡처, DD-012).
        # 행 없는 표를 돌려준다. 조인 키 uid·ts만 타입을 정하고 나머지는 위의 "없는 열"과 같이 null이다.
        return spark.range(0).select(
            *[F.lit(None).cast("string").alias(a) if a == "uid" else F.lit(None).cast("double").alias(a) if a == "ts"
              else F.lit(None).alias(a) for c, a in columns.items()])
    df = spark.read.json(str(path))
    return df.select(*[F.col(f"`{c}`").alias(a) if c in df.columns else F.lit(None).alias(a)
                       for c, a in columns.items()])


def first(col):
    # 같은 uid의 여러 행 중 시각이 가장 이른 행의 값.
    return F.min_by(col, "ts")


def summarize(spark, run_dir):
    """uid별 프로토콜 요약 표들을 돌려준다. 키는 uid다."""
    logs = {}
    dns = read_log(spark, run_dir / "dns.log", {"uid": "uid", "ts": "ts", "query": "query", "qtype_name": "qtype",
                                                "rcode_name": "rcode"})
    logs["dns"] = dns.groupBy("uid").agg(
        F.count("*").alias("dns_n"), first("query").alias("dns_query"), first("qtype").alias("dns_qtype"),
        first("rcode").alias("dns_rcode"), F.max(F.length("query")).alias("dns_query_len_max"),
        F.sum((F.col("rcode") == "NXDOMAIN").cast("int")).alias("dns_nxdomain_n"))
    http = read_log(spark, run_dir / "http.log", {"uid": "uid", "ts": "ts", "method": "method", "host": "host",
                                                  "uri": "uri", "user_agent": "user_agent",
                                                  "status_code": "status", "request_body_len": "req_len",
                                                  "response_body_len": "resp_len"})
    special = F.length("uri") - F.length(F.regexp_replace("uri", URI_SPECIAL, ""))
    logs["http"] = http.groupBy("uid").agg(
        F.count("*").alias("http_n"), first("method").alias("http_method"), first("host").alias("http_host"),
        first("user_agent").alias("http_user_agent"), F.max("status").alias("http_status_max"),
        F.sum((F.col("status") >= 400).cast("int")).alias("http_error_n"),
        F.max(F.length("uri")).alias("http_uri_len_max"),
        F.max(special / F.greatest(F.length("uri"), F.lit(1))).alias("http_uri_special_max"),
        F.sum("req_len").alias("http_req_body_sum"), F.sum("resp_len").alias("http_resp_body_sum"))
    ssl = read_log(spark, run_dir / "ssl.log", {"uid": "uid", "ts": "ts", "version": "version",
                                                "server_name": "sni", "established": "established",
                                                "resumed": "resumed", "sni_matches_cert": "sni_match"})
    logs["ssl"] = ssl.groupBy("uid").agg(
        first("version").alias("ssl_version"), first("sni").alias("ssl_sni"),
        first("established").alias("ssl_established"), first("resumed").alias("ssl_resumed"),
        first("sni_match").alias("ssl_sni_matches_cert"))
    ssh = read_log(spark, run_dir / "ssh.log", {"uid": "uid", "ts": "ts", "auth_success": "auth_success",
                                                "auth_attempts": "auth_attempts", "client": "client"})
    logs["ssh"] = ssh.groupBy("uid").agg(
        first("auth_success").alias("ssh_auth_success"), F.max("auth_attempts").alias("ssh_auth_attempts"),
        first("client").alias("ssh_client"))
    ftp = read_log(spark, run_dir / "ftp.log", {"uid": "uid", "ts": "ts", "command": "command",
                                                "reply_code": "reply_code"})
    logs["ftp"] = ftp.groupBy("uid").agg(
        F.count("*").alias("ftp_n"), F.sum((F.col("command") == "PASS").cast("int")).alias("ftp_pass_n"),
        F.sum((F.col("reply_code") == 530).cast("int")).alias("ftp_fail_n"))
    smb = read_log(spark, run_dir / "smb_mapping.log", {"uid": "uid", "ts": "ts", "share_type": "share_type"})
    logs["smb"] = smb.groupBy("uid").agg(F.count("*").alias("smb_map_n"), first("share_type").alias("smb_share_type"))
    smbf = read_log(spark, run_dir / "smb_files.log", {"uid": "uid", "ts": "ts"})
    logs["smb_files"] = smbf.groupBy("uid").agg(F.count("*").alias("smb_file_n"))
    krb = read_log(spark, run_dir / "kerberos.log", {"uid": "uid", "ts": "ts", "request_type": "request_type",
                                                     "success": "success"})
    logs["kerberos"] = krb.groupBy("uid").agg(
        F.count("*").alias("krb_n"), first("request_type").alias("krb_request_type"),
        F.sum((~F.col("success")).cast("int")).alias("krb_fail_n"))
    dce = read_log(spark, run_dir / "dce_rpc.log", {"uid": "uid", "ts": "ts", "operation": "operation"})
    logs["dce_rpc"] = dce.groupBy("uid").agg(F.count("*").alias("dce_n"), first("operation").alias("dce_operation"))
    ntlm = read_log(spark, run_dir / "ntlm.log", {"uid": "uid", "ts": "ts", "success": "success"})
    logs["ntlm"] = ntlm.groupBy("uid").agg(F.count("*").alias("ntlm_n"),
                                           F.sum((~F.col("success")).cast("int")).alias("ntlm_fail_n"))
    return logs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver", type=Path, default=PROJECT_ROOT / "outputs" / "silver" / "conn_v1")
    parser.add_argument("--zeek-run", default="run-02")
    parser.add_argument("--out", type=Path, default=PROJECT_ROOT / "outputs" / "events" / "tgn_v1")
    # 합성 캡처(DD-008)는 configs/synthetic/captures.syn1.v1.json과 outputs/synthetic/apt_v1/capture-bounds.json.
    parser.add_argument("--captures", type=Path, default=CAPTURES_CONFIG)
    parser.add_argument("--bounds", type=Path, default=BOUNDS_MANIFEST)
    args = parser.parse_args()
    if args.out.exists():
        sys.exit(f"이미 있다: {project_path(args.out)}")

    spark = (SparkSession.builder.master("local[*]").appName("tgn-events")
             .config("spark.sql.session.timeZone", "UTC").config("spark.driver.memory", "8g").getOrCreate())
    spark.sparkContext.setLogLevel("ERROR")
    window_config = windows.load_window_config(windows.PROJECT_CONFIG)
    w = window_config["window_seconds"]
    captures = load_captures(args.captures, args.bounds)
    # 설정의 zeek_run_dir은 run-01을 가리킬 수 있다. 같은 날 폴더의 --zeek-run 실행을 읽는다.
    run_dirs = {c["capture_id"]: PROJECT_ROOT / Path(c["zeek_run_dir"]).parent / args.zeek_run
                for c in json.loads(args.captures.read_text(encoding="utf-8"))["captures"]}

    checks, inputs = [], []
    for cap, run_dir in run_dirs.items():
        inputs.append(file_record(run_dir / "run-manifest.json"))
        silver = spark.read.parquet(str(args.silver / "conn" / f"capture_id={cap}")).withColumn("capture_id", F.lit(cap))
        conn2 = read_log(spark, run_dir / "conn.log", {"uid": "uid", "community_id": "community_id"})
        # run-02 conn이 Silver와 같은 연결 집합인지 확인한다(추가 스크립트가 uid를 바꾸지 않았는지).
        s_n, c_n = silver.count(), conn2.count()
        missing = silver.join(conn2, "uid", "left_anti").count()
        checks.append({"capture_id": cap, "silver_rows": s_n, "run02_conn_rows": c_n, "silver_uid_missing_in_run02": missing})
        print(checks[-1])
        if missing:
            sys.exit(f"{cap}: Silver uid {missing}개가 {args.zeek_run} conn에 없다")

        events = silver.join(conn2.dropDuplicates(["uid"]), "uid", "left")
        for table in summarize(spark, run_dir).values():
            events = events.join(table, "uid", "left")
        events = events.withColumn("window_start", (F.floor(F.col("write_ts") / w) * w).cast("long"))
        labels = window_labels(spark, events.select("capture_id", "window_start"), captures, w,
                               window_config["split_fraction"])
        events = events.join(F.broadcast(labels), ["capture_id", "window_start"], "left")
        # capture_id는 폴더 이름(capture_id=...)으로만 둔다. 파일 안에도 있으면 읽을 때 타입이 충돌한다.
        events.drop("capture_id").write.mode("error").parquet(str(args.out / "events" / f"capture_id={cap}"))

    out = spark.read.parquet(str(args.out / "events"))
    counts = out.groupBy("capture_id").agg(
        F.count("*").alias("events"), *[F.sum(F.col(c).isNotNull().cast("int")).alias(c) for c in
                                        ["community_id", "dns_n", "http_n", "ssl_version", "ssh_auth_success",
                                         "ftp_n", "smb_map_n", "krb_n", "dce_n", "ntlm_n"]],
        F.sum(F.col("split").isNull().cast("int")).alias("split_null")).orderBy("capture_id").collect()
    for r in counts:
        print(r.asDict())
    (args.out / "manifest.json").write_text(json.dumps({
        "dataset": "tgn_events_v1", "decision": "docs/design-decisions/DD-007-tgn-event-graph.md",
        "zeek_run": args.zeek_run, "zeek_run_manifests": inputs,
        "silver_manifests": [file_record(p) for p in sorted((args.silver / "_manifests").glob("*.json"))],
        "configs": [file_record(p) for p in [windows.PROJECT_CONFIG, args.captures, args.bounds]],
        "code": [file_record(Path(__file__).resolve())],
        "uid_checks": checks, "counts": [r.asDict() for r in counts],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    spark.stop()


if __name__ == "__main__":
    main()
