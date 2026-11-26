"""추론 worker(설계 7.1·7.2·8절, 단계 4).

캡처 하나 = 채점 작업 하나다. 순서:
1. 작업 시작 전에 Registry alias를 실제 버전으로 풀어 고정한다. 작업 중 alias가 바뀌어도 이 버전을 쓴다.
2. 트랜잭션 1: 작업 키(캡처, 입력 manifest 해시, 묶음)로 작업 행을 만든다(running). 이미 succeeded면 건너뛴다.
3. 채점 → (set에 queue_eligibility 항목이 있으면) 큐 자격 라벨 → 결합 큐(트랜잭션 밖, 오래 걸림).
   라벨이 붙은 창은 결합 큐에서 빠지고, 창 점수는 라벨(split)과 함께 모두 저장한다(zeek_ad/queue_eligibility.py).
4. 트랜잭션 2: 작업 행 잠금 → 창 점수·사건·succeeded 표시를 한 번에 commit한다.
   commit 전에 죽으면 결과는 하나도 남지 않고 작업 행만 running으로 남는다. 다시 돌리면 그 작업을 이어받는다.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import mlflow
from psycopg.types.json import Jsonb

from zeek_ad.fusion import picked_score
from zeek_ad.provenance import PROJECT_ROOT, file_record, sha256
from zeek_ad.queue_eligibility import fingerprint_record

REGISTERED_NAME = "zeekad-fusion"


def utc(seconds):
    return datetime.fromtimestamp(int(seconds), timezone.utc)


def resolve_bundle(alias):
    """alias → 버전 고정 → 묶음을 받아 manifest 해시와 코드 호환성을 확인한다."""
    client = mlflow.MlflowClient()
    mv = client.get_model_version_by_alias(REGISTERED_NAME, alias)
    uri = f"models:/{REGISTERED_NAME}/{mv.version}"  # alias가 아니라 버전 번호로 받는다
    local = Path(mlflow.artifacts.download_artifacts(uri))
    manifest_path = local / "artifacts" / "manifest.json"
    manifest_sha = sha256(manifest_path)
    if manifest_sha != mv.tags.get("manifest_sha256"):
        raise ValueError("받은 묶음의 manifest 해시가 Registry 태그와 다르다")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    # worker는 이 저장소의 zeek_ad 코드를 import한다. 묶음을 만든 코드와 같아야 같은 계산이다.
    changed = [c["path"] for c in manifest["compatibility"]["code"] if sha256(PROJECT_ROOT / c["path"]) != c["sha256"]]
    if changed:
        raise ValueError(f"묶음을 만든 뒤 코드가 바뀌었다: {changed}")
    model = mlflow.pyfunc.load_model(str(local))
    return {"bundle_id": f"{REGISTERED_NAME}/{mv.version}", "version": int(mv.version), "alias": alias,
            "manifest": manifest, "manifest_sha256": manifest_sha, "model": model.unwrap_python_model()}


def input_fingerprint(gold_dir, graph_dir, bounds_path, capture_id, queue_eligibility=None):
    """작업 입력을 가리키는 해시. 입력 manifest(Gold·그래프)와 캡처 경계 파일이 같으면 같은 입력이다.

    queue_eligibility: 큐 자격 규칙을 쓰는 작업이면 queue_eligibility.fingerprint_record 값(규칙 설정·자산 설정·
    연결 자료 manifest 해시). None이면 기록에 키를 넣지 않는다. 그래서 규칙이 없는 작업(CIC·합성, 옛 리비전)의
    지문은 이 인자가 생기기 전과 같다.
    """
    record = {"capture_id": capture_id,
              "gold_manifest": file_record(Path(gold_dir) / "manifest.json")["sha256"],
              "graph_manifest": file_record(Path(graph_dir) / "manifest.json")["sha256"],
              "bounds": sha256(bounds_path)}
    if queue_eligibility is not None:
        record["queue_eligibility"] = queue_eligibility
    return hashlib.sha256(json.dumps(record, sort_keys=True).encode("utf-8")).hexdigest(), record


def set_input_fingerprint(cfg, capture_id, root=PROJECT_ROOT):
    """입력 묶음 정의의 set 하나(cfg)로 지문을 계산한다. 채점 worker와 live_agent.revision_for_job이 함께 쓴다.

    경로는 root 기준이다(절대 경로면 그대로). set에 queue_eligibility 항목이 있을 때만 규칙 입력이 지문에 들어간다.
    """
    root = Path(root)
    entry = cfg.get("queue_eligibility")
    extra = None if entry is None else fingerprint_record(entry, capture_id, root)
    return input_fingerprint(root / cfg["gold_dir"], root / cfg["graph_dir"], root / cfg["bounds"], capture_id, extra)


def upsert_bundle(conn, b):
    conn.execute("""INSERT INTO model_bundle (bundle_id, registry_name, registry_version, manifest_sha256, manifest)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (bundle_id) DO NOTHING""",
                 (b["bundle_id"], REGISTERED_NAME, b["version"], b["manifest_sha256"], Jsonb(b["manifest"])))
    row = conn.execute("SELECT manifest_sha256 FROM model_bundle WHERE bundle_id = %s", (b["bundle_id"],)).fetchone()
    if row[0] != b["manifest_sha256"]:
        raise ValueError("같은 버전으로 다른 묶음이 이미 기록돼 있다")


def open_job(conn, capture_id, input_sha, bundle_id):
    """짧은 트랜잭션 1: 작업 행을 만들거나 찾는다. 반환: (job_id, 'new'|'resume'|'done').

    commit해서 다른 사람이 running 작업을 볼 수 있게 한다. 결과는 아직 쓰지 않는다.
    """
    with conn.transaction():
        created = conn.execute("""INSERT INTO scoring_job (capture_id, input_manifest_sha256, bundle_id, status)
                                  VALUES (%s, %s, %s, 'running')
                                  ON CONFLICT (capture_id, input_manifest_sha256, bundle_id) DO NOTHING
                                  RETURNING job_id""", (capture_id, input_sha, bundle_id)).fetchone()
        if created:
            return created[0], "new"
        job_id, status = conn.execute(
            """SELECT job_id, status FROM scoring_job
               WHERE capture_id = %s AND input_manifest_sha256 = %s AND bundle_id = %s""",
            (capture_id, input_sha, bundle_id)).fetchone()
        if status == "succeeded":
            return job_id, "done"
        # 지난 실행이 commit 전에 멈췄다(running) 또는 실패했다(failed). 이어받는다.
        conn.execute("UPDATE scoring_job SET status = 'running', started_at = now(), finished_at = NULL, error = NULL "
                     "WHERE job_id = %s", (job_id,))
        return job_id, "resume"


def lock_job(conn, job_id):
    """트랜잭션 2의 시작: 작업 행을 잠그고 아직 끝나지 않았는지 다시 본다.

    두 worker가 같은 작업을 동시에 채점해도, 먼저 commit한 쪽만 결과를 쓴다. 뒤에 온 쪽은 succeeded를 보고 멈춘다.
    반환: 결과를 써도 되면 True.
    """
    status = conn.execute("SELECT status FROM scoring_job WHERE job_id = %s FOR UPDATE", (job_id,)).fetchone()[0]
    if status == "succeeded":
        return False
    # commit되지 않은 결과는 남지 않지만, 규칙을 분명히 하려고 이 작업의 이전 결과를 지우고 쓴다.
    conn.execute("DELETE FROM incident WHERE job_id = %s", (job_id,))
    conn.execute("DELETE FROM window_score WHERE job_id = %s", (job_id,))
    return True


def write_results(conn, job_id, scores, fused, sources, queues, fault=None):
    """창 점수(COPY로 한 번에), 결합 사건, 사건 창을 쓴다. 호출한 쪽 트랜잭션 안에서 실행된다.

    fault: 장애 복구 시험용 훅(scripts/test_worker_recovery.py). 창 점수를 쓴 직후 fault("mid_write")를 부른다.
    """
    with conn.cursor() as cur:
        with cur.copy("COPY window_score (job_id, model_name, asset_id, role, window_start, split, score, is_candidate)"
                      " FROM STDIN") as copy:
            for r in scores.itertuples(index=False):
                copy.write_row((job_id, r.model_name, r.asset_id, r.role, utc(r.window_start), r.split,
                                float(r.score), bool(r.is_candidate)))
        if fault:
            fault("mid_write")
        for rank, inc in enumerate(fused, 1):
            picked, *also = sources[inc.incident_id]
            cur.execute("""INSERT INTO incident (job_id, incident_id, queue_rank, asset_id, role, first_start, last_end,
                                                 picked_by, also_flagged_by, model_score)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (job_id, inc.incident_id, rank, inc.asset_id, inc.role, utc(inc.first_start),
                         utc(inc.last_end), picked, sorted(set(also)), float(picked_score(queues[picked], inc))))
            cur.executemany("INSERT INTO incident_window (job_id, incident_id, window_start) VALUES (%s, %s, %s)",
                            [(job_id, inc.incident_id, utc(w)) for w in inc.windows])
    conn.execute("UPDATE scoring_job SET status = 'succeeded', finished_at = now() WHERE job_id = %s", (job_id,))


def mark_failed(conn, capture_id, input_sha, bundle_id, error):
    # 결과 트랜잭션은 이미 롤백됐다. 실패 기록은 별도 트랜잭션으로 남긴다.
    conn.execute("""INSERT INTO scoring_job (capture_id, input_manifest_sha256, bundle_id, status, error, finished_at)
                    VALUES (%s, %s, %s, 'failed', %s, now())
                    ON CONFLICT (capture_id, input_manifest_sha256, bundle_id)
                    DO UPDATE SET status = 'failed', error = EXCLUDED.error, finished_at = now()
                    WHERE scoring_job.status <> 'succeeded'""",
                 (capture_id, input_sha, bundle_id, error[:2000]))
