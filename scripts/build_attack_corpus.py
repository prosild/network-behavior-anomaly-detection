"""ATT&CK 기법 문서를 프로젝트 DB(rag.attack_document)에 넣는다(단계 5a, DD-002 2절, 설계 질문 기록 Q37).

1. 사용자 RAG 실습 DB(attack_rag.attack_documents)에서 technique 706행을 읽어 스냅샷으로 저장한다.
   비밀번호는 PGPASSWORD 환경 변수로 받는다(실습 DB 계정, 코드에 넣지 않는다).
2. ATT&CK STIX 원본(Enterprise 20.1)을 outputs/rag/에 복사하고 버전·해시를 확인한다.
3. 탐지 절을 다시 만든다: 기법 ← detects ← detection strategy → analytic → 로그 소스(데이터 구성 요소).
   실습 파서는 v18에서 없어진 x_mitre_detection 필드를 읽어 706건 모두 비어 있었다.
4. 실습 본문의 빈 탐지 절을 새 탐지 절로 바꿔 한 트랜잭션으로 넣는다(전부 지우고 다시).
예: PGPASSWORD=postgres python scripts/build_attack_corpus.py
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys

import psycopg
from psycopg.types.json import Jsonb

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import connect  # noqa: E402
from zeek_ad.provenance import project_path, sha256  # noqa: E402

PRACTICE_STIX = Path("/mnt/c/Users/pgils/src/RAG_pratice/enterprise-attack.json")
OUT = PROJECT_ROOT / "outputs" / "rag" / "attack_v20.1"
ATTACK_VERSION = "20.1"
EMPTY_DETECTION = "## Detection\nNo detection guidance available."


def external_id(obj):
    return next((r["external_id"] for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
                None)


def detection_sections(bundle):
    """{기법 stix_id: (탐지 절 마크다운, 데이터 구성 요소 목록)}."""
    objs = {o["id"]: o for o in bundle["objects"]}
    active = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")  # noqa: E731
    out = {}
    for rel in bundle["objects"]:
        if rel["type"] != "relationship" or rel["relationship_type"] != "detects":
            continue
        strategy, technique = objs[rel["source_ref"]], rel["target_ref"]
        if not active(strategy):
            continue
        lines = [f"## Detection", f"### Strategy {external_id(strategy)}: {strategy['name']}"]
        components = set()
        for ref in strategy.get("x_mitre_analytic_refs", []):
            a = objs.get(ref)
            if not a or not active(a):
                continue
            sources = []
            for ls in a.get("x_mitre_log_source_references", []):
                dc = objs.get(ls["x_mitre_data_component_ref"], {}).get("name", "unknown")
                components.add(dc)
                sources.append(f"{dc} ({ls['name']}: {ls['channel']})")
            lines.append(f"- **{external_id(a)}** [{', '.join(a.get('x_mitre_platforms', []))}] "
                         f"{a.get('description', '').strip()}")
            if sources:
                lines.append(f"  - Log sources: {'; '.join(sources)}")
        out[technique] = ("\n".join(lines), sorted(components))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--practice-host", default="127.0.0.1")
    parser.add_argument("--practice-port", type=int, default=5432)
    parser.add_argument("--stix", type=Path, default=PRACTICE_STIX)
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    # 1. 실습 DB 스냅샷(읽기만 한다).
    with psycopg.connect(host=args.practice_host, port=args.practice_port, dbname="attack_rag", user="postgres") as conn:
        cols = ["attack_id", "stix_id", "name", "tactics", "platforms", "content", "metadata"]
        rows = [dict(zip(cols, r)) for r in conn.execute(
            f"SELECT {', '.join(cols)} FROM attack_documents WHERE category = 'technique' ORDER BY attack_id")]
    snapshot = OUT / "practice_documents.jsonl"
    snapshot.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")

    # 2. STIX 원본 복사와 버전 확인.
    stix = OUT / "enterprise-attack.json"
    shutil.copyfile(args.stix, stix)
    bundle = json.loads(stix.read_text(encoding="utf-8"))
    version = next(o["x_mitre_version"] for o in bundle["objects"] if o["type"] == "x-mitre-collection")
    if version != ATTACK_VERSION:
        sys.exit(f"ATT&CK 버전이 {version}이다(기대 {ATTACK_VERSION})")
    techniques = {o["id"]: o for o in bundle["objects"] if o["type"] == "attack-pattern"
                  and not o.get("revoked") and not o.get("x_mitre_deprecated")}

    # 3·4. 탐지 절을 바꾼 최종 본문.
    detections = detection_sections(bundle)
    problems, docs = [], []
    for r in rows:
        t = techniques.get(r["stix_id"])
        if t is None or external_id(t) != r["attack_id"]:
            problems.append(f"{r['attack_id']}: STIX 원본에 없거나 ID가 다르다")
            continue
        if EMPTY_DETECTION not in r["content"]:
            problems.append(f"{r['attack_id']}: 빈 탐지 절 표시가 없다")
            continue
        detection, components = detections.get(r["stix_id"], ("## Detection\nNo detection strategy in ATT&CK 20.1.", []))
        docs.append({**r, "detection": detection, "data_components": components,
                     "document": r["content"].replace(EMPTY_DETECTION, detection),
                     "row_sha256": hashlib.sha256(r["content"].encode("utf-8")).hexdigest()})
    if problems:
        sys.exit("\n".join(problems[:20]))
    source = {"practice_snapshot": {"path": project_path(snapshot), "sha256": sha256(snapshot), "rows": len(rows)},
              "stix": {"path": project_path(stix), "sha256": sha256(stix), "attack_version": version}}

    with connect("zeekad_worker", autocommit=True) as conn:
        with conn.transaction():
            conn.execute("DELETE FROM rag.attack_document")
            with conn.cursor() as cur:
                cur.executemany(
                    """INSERT INTO rag.attack_document (attack_id, stix_id, attack_version, name, tactics, platforms,
                           is_subtechnique, url, data_components, detection, document, source)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    [(d["attack_id"], d["stix_id"], version, d["name"], d["tactics"] or [], d["platforms"] or [],
                      bool(d["metadata"].get("is_subtechnique")), d["metadata"].get("url"), d["data_components"],
                      d["detection"], d["document"], Jsonb({**source, "practice_row_sha256": d["row_sha256"]}))
                     for d in docs])
    no_strategy = sum("No detection strategy" in d["detection"] for d in docs)
    lengths = sorted(len(d["document"]) for d in docs)
    print(json.dumps({"documents": len(docs), "attack_version": version, "without_strategy": no_strategy,
                      "document_chars": {"median": lengths[len(lengths) // 2], "p95": lengths[int(len(lengths) * 0.95)],
                                         "max": lengths[-1]},
                      "snapshot_sha256": source["practice_snapshot"]["sha256"][:12],
                      "stix_sha256": source["stix"]["sha256"][:12]}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
