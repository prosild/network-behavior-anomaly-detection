"""만든 결합 묶음 폴더를 MLflow Registry `zeekad-fusion`의 새 버전으로 등록한다(설계 8절, 단계 7).

묶음은 이 PC에서 scripts/build_bundle.py로 만든다(CIC 다섯 캡처 재현 검사 포함). 배포 VM에는 묶음 폴더
(outputs/bundles/<결합 설정 ID>/<시각>/: model/, manifest.json, reproduction.json)를 옮겨 이 스크립트로 등록한다.
등록 전에 두 가지를 확인한다.
- 재현 검사를 통과한 묶음인가(reproduction.json의 passed).
- 지금 코드가 묶음을 만든 코드와 같은가(manifest의 코드 해시. worker도 채점 전에 같은 검사를 한다).
승격(alias)은 손으로 한다. --alias를 줄 때만 붙인다. 바꾸기: python scripts/register_bundle.py --set-alias champion 3

예: python scripts/register_bundle.py outputs/bundles/fusion_v2/20261119T070000Z --alias challenger
    python scripts/register_bundle.py --set-alias champion 2
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
import mlflow  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from zeek_ad.db import mlflow_tracking_uri  # noqa: E402
from zeek_ad.provenance import sha256  # noqa: E402

REGISTERED_NAME = "zeekad-fusion"
EXPERIMENT = "zeek-ad-stage4"


def code_changes(manifest):
    return [c["path"] for c in manifest["compatibility"]["code"] if sha256(PROJECT_ROOT / c["path"]) != c["sha256"]]


def register(bundle_dir, alias=None):
    """묶음 폴더를 새 버전으로 등록한다. 반환: 버전 번호."""
    bundle_dir = Path(bundle_dir)
    model_dir = bundle_dir / "model"
    manifest_path = model_dir / "artifacts" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    repro = json.loads((bundle_dir / "reproduction.json").read_text(encoding="utf-8"))
    if not repro.get("passed"):
        sys.exit("재현 검사를 통과하지 않은 묶음이다")
    changed = code_changes(manifest)
    if changed:
        sys.exit(f"지금 코드가 묶음을 만든 코드와 다르다: {changed}")
    manifest_sha = sha256(manifest_path)

    mlflow.set_tracking_uri(mlflow_tracking_uri())
    if mlflow.get_experiment_by_name(EXPERIMENT) is None:
        mlflow.create_experiment(EXPERIMENT, artifact_location=(PROJECT_ROOT / "outputs" / "mlflow" / "artifacts"
                                                                 / "stage4").as_uri())
    mlflow.set_experiment(EXPERIMENT)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with mlflow.start_run(run_name=f"bundle-{manifest['bundle']}-{stamp}") as run:
        mlflow.set_tags({"stage": "7", "bundle": manifest["bundle"], "manifest_sha256": manifest_sha,
                         "bundle_dir": bundle_dir.name})
        mlflow.log_params({f"threshold.{m['name']}": m["threshold"] for m in manifest["models"]})
        mlflow.log_param("overlap_policy", manifest["fusion"].get("overlap_policy", "skip"))
        mlflow.log_dict(repro, "reproduction.json")
        mlflow.log_artifacts(str(model_dir), artifact_path="fusion_bundle")
    mv = mlflow.register_model(f"runs:/{run.info.run_id}/fusion_bundle", REGISTERED_NAME)
    client = mlflow.MlflowClient()
    client.set_model_version_tag(REGISTERED_NAME, mv.version, "manifest_sha256", manifest_sha)
    client.set_model_version_tag(REGISTERED_NAME, mv.version, "bundle", manifest["bundle"])
    client.set_model_version_tag(REGISTERED_NAME, mv.version, "reproduced",
                                 f"cic17 5 captures, max abs diff {max(repro['max_abs_diff'].values())}")
    if alias:
        client.set_registered_model_alias(REGISTERED_NAME, alias, mv.version)
    return int(mv.version)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bundle_dir", nargs="?", type=Path)
    parser.add_argument("--alias", help="등록하면서 붙일 alias")
    parser.add_argument("--set-alias", nargs=2, metavar=("ALIAS", "VERSION"), help="등록 없이 alias만 옮긴다(승격·롤백)")
    args = parser.parse_args()
    if args.set_alias:
        alias, version = args.set_alias
        mlflow.set_tracking_uri(mlflow_tracking_uri())
        client = mlflow.MlflowClient()
        before = None
        try:
            before = client.get_model_version_by_alias(REGISTERED_NAME, alias).version
        except mlflow.exceptions.MlflowException:
            pass
        client.set_registered_model_alias(REGISTERED_NAME, alias, version)
        mv = client.get_model_version(REGISTERED_NAME, version)
        print(f"{REGISTERED_NAME}@{alias}: 버전 {before} → {version} ({mv.tags.get('bundle', '?')}). "
              "실행 중인 작업은 바뀌지 않고, 다음 채점 작업부터 이 버전을 쓴다")
        return
    if not args.bundle_dir:
        parser.error("묶음 폴더나 --set-alias가 필요하다")
    version = register(args.bundle_dir, args.alias)
    print(f"registered {REGISTERED_NAME} version {version}" + (f" (alias {args.alias})" if args.alias else ""))


if __name__ == "__main__":
    main()
