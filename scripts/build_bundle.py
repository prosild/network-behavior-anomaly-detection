"""결합 배포 묶음을 만들고, 원래 평가 점수를 그대로 재현하면 MLflow Registry에 등록한다(설계 8절, 단계 4·7).

1. 구성 요소 모으기: 꼬리 희귀도 v2(월요일 train 분포), Transformer v2(체크포인트 + 전처리·표준화 값),
   TGN recon(parameter + 인코딩), 임계값(각 run의 보류 p95), 사건·결합 정책(--fusion, 기본 fusion.v1.json).
2. manifest.json: 특징 스키마, 임계값, 사건 정책, 출처 run, 코드·패키지 버전, 파일 해시.
3. 로컬에 pyfunc 모델로 저장 → 다시 불러와 CIC 다섯 캡처의 창 점수를 원래 run과 대조(차이 0이어야 함).
   결과는 <묶음 폴더>/reproduction.json. 묶음 폴더는 outputs/bundles/<결합 설정 ID>/<시각>/.
4. --register: Registry 모델 `zeekad-fusion`의 새 버전으로 등록한다(scripts/register_bundle.py와 같은 함수).
   승격은 손으로 한다(설계 8절 "수동 승격"). --alias를 줄 때만 그 alias를 붙인다.
   배포 VM에는 묶음 폴더를 옮겨 scripts/register_bundle.py로 등록한다(VM에는 재현에 쓰는 CIC 자료가 없다).
코드가 바뀌면 묶음을 다시 만든다. worker는 묶음 manifest의 코드 해시와 지금 코드가 같아야 쓴다(zeek_ad/worker.py).
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import sys

os.environ.setdefault("MLFLOW_DISABLE_AGENT_HINT", "1")
import mlflow  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from zeek_ad.baselines import Preprocessor, TailRarity  # noqa: E402
from zeek_ad.bundle import KEYS, FusionBundle  # noqa: E402
from zeek_ad.db import mlflow_tracking_uri  # noqa: E402
from zeek_ad.evaluation import MAX_INCIDENT_SECONDS, TIE_KEY_VERSION, TIE_SALT, WINDOW_SECONDS  # noqa: E402
from zeek_ad.provenance import file_record, project_path, sha256  # noqa: E402
from zeek_ad.sequences import Scaler  # noqa: E402

EVAL = PROJECT_ROOT / "outputs" / "eval"
GOLD_V2 = PROJECT_ROOT / "outputs" / "gold" / "conn_features_v2"
GRAPH = PROJECT_ROOT / "outputs" / "graphs" / "tgn_v1"
BOUNDS = PROJECT_ROOT / "manifests" / "cic-ids-2017.capture-bounds.v1.json"
FUSION = PROJECT_ROOT / "configs" / "models" / "fusion.v1.json"   # 기본값. --fusion으로 바꾼다
TF_CONFIG = PROJECT_ROOT / "configs" / "models" / "transformer.v2.json"
TGN_CONFIG = PROJECT_ROOT / "configs" / "models" / "tgn.v1.json"
REGISTERED_NAME = "zeekad-fusion"
EXPERIMENT = "zeek-ad-stage4"
PACKAGES = ["mlflow==3.17.2", "numpy==2.5.4", "pandas==2.3.3", "pyarrow==25.0.1", "scikit-learn==1.9.1",
            "torch==2.15.0", "torch-geometric==2.8.1"]
CODE_FILES = ["baselines.py", "bundle.py", "evaluation.py", "fusion.py", "gold_features.py", "provenance.py",
              "sequences.py", "tgn_model.py", "transformer_model.py"]


def collect(work, fusion_path):
    """구성 요소 파일을 work/에 만들고 {artifact 이름: 경로}와 모델 정보를 돌려준다."""
    fusion = json.loads(Path(fusion_path).read_text(encoding="utf-8"))
    runs = {m["name"]: EVAL / m["cic_run"] for m in fusion["models"]}
    gold_manifest = json.loads((GOLD_V2 / "manifest.json").read_text(encoding="utf-8"))
    features = gold_manifest["features"]
    gold = pd.read_parquet(GOLD_V2 / "windows")
    gold["capture_id"] = gold["capture_id"].astype(str)
    gold = gold.sort_values(KEYS).reset_index(drop=True)  # build_sequences.py와 같은 순서로 적합한다
    train = gold[gold.split == "train"]
    art = {}

    # 꼬리 희귀도: 특징별 정렬된 월요일 train 값이 모델 전부다.
    tail = TailRarity(features).fit(train)
    art["tail_rarity_v2"] = work / "tail_rarity_v2.npz"
    np.savez(art["tail_rarity_v2"], **tail.sorted_)

    # Transformer: 전처리(log1p + 중앙값 대치)와 표준화 값을 다시 적합하고, 시퀀스 manifest의 값과 같은지 본다.
    pre = Preprocessor(features).fit(train)
    scaler = Scaler().fit(pre.transform(train)[features].to_numpy())
    seq_manifest = json.loads((PROJECT_ROOT / "outputs" / "sequences" / "transformer_v2" / "manifest.json")
                              .read_text(encoding="utf-8"))
    if pre.params() != seq_manifest["preprocess"] or scaler.params(features) != seq_manifest["scaler"]:
        sys.exit("다시 적합한 전처리·표준화 값이 학습 때(시퀀스 manifest)와 다르다")
    art["transformer_v2_preprocess"] = work / "transformer_v2.preprocess.json"
    art["transformer_v2_preprocess"].write_text(json.dumps(
        {"impute_median": pre.medians_.to_dict(), "log1p": pre.log_features}, indent=2) + "\n", encoding="utf-8")
    art["transformer_v2_scaler"] = work / "transformer_v2.scaler.npz"
    np.savez(art["transformer_v2_scaler"], mean=scaler.mean_, std=scaler.std_)
    art["transformer_v2_config"] = TF_CONFIG
    art["transformer_v2_checkpoint"] = next(runs["transformer_v2"].glob("*.pt"))

    # TGN: 학습 parameter와 인코딩(어휘·표준화). 그래프는 같은 인코딩으로 만든 것만 받는다.
    art["tgn_config"] = TGN_CONFIG
    art["tgn_encoding"] = GRAPH / "encoding.json"
    art["tgn_checkpoint"] = next(runs["tgn_recon"].glob("*.pt"))
    art["fusion_config"] = fusion_path

    models = []
    for name, run in runs.items():
        metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
        models.append({"name": name, "threshold": metrics["threshold"], "threshold_rule": metrics["threshold_rule"],
                       "source_eval_run": project_path(run)})
    return art, models, features, gold_manifest


def write_manifest(work, art, models, features, gold_manifest):
    fusion = json.loads(Path(art["fusion_config"]).read_text(encoding="utf-8"))
    manifest = {
        "bundle": fusion["config_id"], "decision": fusion["decision"],
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "models": models,
        "feature_schema": {"gold_feature_version": gold_manifest["feature_version"], "gold_features": features,
                           "tgn_encoding_sha256": sha256(GRAPH / "encoding.json")},
        "incident_policy": {"window_seconds": WINDOW_SECONDS, "max_incident_seconds": MAX_INCIDENT_SECONDS,
                            "tie_salt": TIE_SALT, "tie_key_version": TIE_KEY_VERSION,
                            "exclude_split": "capture_edge", "candidate": "score >= threshold"},
        "fusion": fusion,
        "compatibility": {"python": platform.python_version(), "packages": PACKAGES,
                          "code": [file_record(PROJECT_ROOT / "zeek_ad" / f) for f in CODE_FILES],
                          "input": "Gold v2 windows(capture_id 분할) + TGN 그래프(같은 encoding.json) + 캡처 packet_time_min"},
        "files": {k: file_record(v) for k, v in art.items()},
    }
    path = work / "manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def reproduce(model_dir, fusion):
    """저장한 묶음을 다시 불러와 다섯 캡처의 창 점수가 원래 평가 run과 같은지 본다."""
    bundle = mlflow.pyfunc.load_model(str(model_dir)).unwrap_python_model()
    bounds = {c["capture_id"]: c for c in json.loads(BOUNDS.read_text(encoding="utf-8"))["captures"]}
    refs = {}
    for m in fusion["models"]:
        ref = pd.read_parquet(EVAL / m["cic_run"] / "scores.parquet")
        ref["capture_id"] = ref["capture_id"].astype(str)
        refs[m["name"]] = ref
    worst = {}
    for cap, b in bounds.items():
        scores = bundle.score_capture(cap, GOLD_V2, GRAPH, b["packet_time_min"])
        for name, ref in refs.items():
            got = scores[scores.model_name == name].merge(ref[KEYS + ["score"]], on=KEYS, how="outer",
                                                          suffixes=("", "_ref"), indicator=True)
            got = got[got.capture_id == cap]
            if (got._merge != "both").any():
                sys.exit(f"{cap} {name}: 창 집합이 원래 run과 다르다")
            worst[name] = max(worst.get(name, 0.0), float(np.abs(got.score - got.score_ref).max()))
        print(f"reproduced {cap}", flush=True)
    return worst


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fusion", type=Path, default=FUSION, help="결합 설정(기본 fusion.v1.json)")
    parser.add_argument("--register", action="store_true", help="재현 확인 뒤 MLflow Registry에 새 버전으로 등록한다")
    parser.add_argument("--alias", help="등록하면서 붙일 alias(예: challenger). 없으면 붙이지 않는다")
    args = parser.parse_args()
    fusion = json.loads(args.fusion.read_text(encoding="utf-8"))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = PROJECT_ROOT / "outputs" / "bundles" / fusion["config_id"].replace(".", "_") / stamp
    work = root / "components"
    work.mkdir(parents=True)
    art, models, features, gold_manifest = collect(work, args.fusion.resolve())
    art["manifest"] = write_manifest(work, art, models, features, gold_manifest)
    model_kwargs = {"python_model": FusionBundle(), "artifacts": {k: str(v) for k, v in art.items()},
                    "code_paths": [str(PROJECT_ROOT / "zeek_ad")], "pip_requirements": PACKAGES}
    mlflow.pyfunc.save_model(path=str(root / "model"), **model_kwargs)

    worst = reproduce(root / "model", fusion)
    print("max abs diff", worst)
    shutil.copy(art["manifest"], root / "manifest.json")
    (root / "reproduction.json").write_text(json.dumps({
        "checked": "cic17 5 captures window scores vs original eval runs", "max_abs_diff": worst,
        "passed": all(v <= 1e-9 for v in worst.values())}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if any(v > 1e-9 for v in worst.values()):
        sys.exit("원래 평가 점수와 다르다. 등록하지 않는다")
    if not args.register:
        print(f"-> {project_path(root)} (등록하지 않음. 등록: python scripts/register_bundle.py {project_path(root)})")
        return
    from register_bundle import register
    version = register(root, args.alias)
    print(f"registered {REGISTERED_NAME} version {version}" + (f" (alias {args.alias})" if args.alias else ""))
    print(f"-> {project_path(root)}")


if __name__ == "__main__":
    main()
