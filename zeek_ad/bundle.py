"""배포 묶음(설계 8절): 모델 + 전처리 + 특징 스키마 + 임계값 + 사건 정책 + 호환성 정보.

결합 v1(DD-009) 묶음은 꼬리 희귀도 v2, Transformer v2, TGN recon 세 모델과 각 임계값, 사건 묶기·결합 규칙을 담는다.
MLflow pyfunc 모델로 Registry에 등록한다. 추론 worker는 `mlflow.pyfunc.load_model("models:/이름@alias")`로 받고
`unwrap_python_model()`로 이 클래스의 메서드를 직접 쓴다.

predict 입력은 캡처 한 행에 하나다: capture_id, gold_dir(Gold v2), graph_dir(TGN 그래프), packet_time_min.
출력은 모델별 창 점수(긴 표)다. 사건 큐는 build_queue로 만든다.
"""

import json
from pathlib import Path

import mlflow
import numpy as np
import pandas as pd

KEYS = ["capture_id", "asset_id", "role", "window_start"]
MODEL_ORDER = ["tgn_recon", "tail_rarity_v2", "transformer_v2"]


def read_capture_gold(gold_dir, capture_id):
    gold = pd.read_parquet(Path(gold_dir) / "windows", filters=[("capture_id", "==", capture_id)])
    gold["capture_id"] = gold["capture_id"].astype(str)
    return gold.sort_values(KEYS).reset_index(drop=True)


class FusionBundle(mlflow.pyfunc.PythonModel):
    """세 모델과 정책을 한 단위로 싣는다. 무거운 import는 load_context 안에서 한다."""

    def load_context(self, context):
        import torch

        from zeek_ad.baselines import Preprocessor, TailRarity
        from zeek_ad.sequences import Scaler
        from zeek_ad.transformer_model import build_model

        a = context.artifacts
        self.manifest = json.loads(Path(a["manifest"]).read_text(encoding="utf-8"))
        self.features = self.manifest["feature_schema"]["gold_features"]
        self.thresholds = {m["name"]: m["threshold"] for m in self.manifest["models"]}

        tail = np.load(a["tail_rarity_v2"])
        self.tail = TailRarity(self.features)
        self.tail.sorted_ = {f: tail[f] for f in self.features}

        pre = json.loads(Path(a["transformer_v2_preprocess"]).read_text(encoding="utf-8"))
        self.pre = Preprocessor(self.features)
        self.pre.medians_ = pd.Series(pre["impute_median"])[self.pre.features]
        scaler = np.load(a["transformer_v2_scaler"])
        self.scaler = Scaler()
        self.scaler.mean_, self.scaler.std_ = scaler["mean"], scaler["std"]
        self.tf_config = json.loads(Path(a["transformer_v2_config"]).read_text(encoding="utf-8"))
        n = len(self.features)
        self.transformer = build_model(self.tf_config, n_in=n + 3, n_out=n)
        self.transformer.load_state_dict(torch.load(a["transformer_v2_checkpoint"], weights_only=True)["state_dict"])
        self.transformer.eval()

        self.tgn_config = json.loads(Path(a["tgn_config"]).read_text(encoding="utf-8"))
        self.tgn_encoding_path = Path(a["tgn_encoding"])
        self.tgn_params = torch.load(a["tgn_checkpoint"], weights_only=True)["parameters"]
        self.fusion = json.loads(Path(a["fusion_config"]).read_text(encoding="utf-8"))

    def score_tail(self, gold):
        return self.tail.score(gold)

    def score_transformer(self, gold, packet_time_min):
        """같은 캡처의 직전 12칸 맥락으로 예측 오차를 낸다. gold는 한 캡처, 키 순서로 정렬된 표다."""
        import torch
        from torch.utils.data import DataLoader

        from zeek_ad.sequences import build_sequences
        from zeek_ad.transformer_model import WindowSequences, predict_scores

        w = self.manifest["incident_policy"]["window_seconds"]
        z = self.scaler.transform(self.pre.transform(gold)[self.features].to_numpy())
        role = (gold["role"] == "responder").to_numpy(dtype=float)
        cap = gold.capture_id.iloc[0]
        x, y = build_sequences(list(gold[KEYS].itertuples(index=False, name=None)), z, role,
                               {cap: int(float(packet_time_min) // w * w)}, w,
                               self.tf_config["sequence"]["context_windows"])
        loader = DataLoader(WindowSequences(x, y, np.ones(len(x), dtype=bool)), batch_size=512, shuffle=False)
        return predict_scores(self.transformer, loader, torch.device("cpu")).astype(float)

    def score_tgn(self, graph_dir, capture_id):
        """그래프에서 그 캡처의 이벤트만 빈 메모리부터 흘려 창별 recon 최댓값을 낸다."""
        from zeek_ad.provenance import sha256
        from zeek_ad.tgn_model import EventTGN, load_graph, score_capture, window_scores

        graph_dir = Path(graph_dir)
        if sha256(graph_dir / "encoding.json") != sha256(self.tgn_encoding_path):
            raise ValueError("그래프 인코딩이 묶음과 다르다(어휘·표준화 값이 다른 그래프)")
        data, node_x, index, encoding = load_graph(graph_dir)
        tgn = EventTGN(self.tgn_config, encoding, num_nodes=node_x.shape[0], node_dim=node_x.shape[1],
                       raw_msg_dim=data.msg.shape[1])
        tgn.load_parameter_state(self.tgn_params)
        pos = np.flatnonzero((index.capture_id == capture_id).to_numpy())
        start, end = int(pos[0]), int(pos[-1]) + 1
        if end - start != len(pos):
            raise ValueError(f"{capture_id} 이벤트가 이어져 있지 않다")
        recon, shift_src, shift_dst = score_capture(tgn, data, node_x, start, end,
                                                    self.tgn_config["training"]["batch_events"])
        win = window_scores(index.iloc[start:end], recon, shift_src, shift_dst)
        return win[KEYS + ["recon"]]

    def score_capture(self, capture_id, gold_dir, graph_dir, packet_time_min):
        """캡처 하나의 세 모델 창 점수(긴 표: model_name, 키, split, score, is_candidate)."""
        gold = read_capture_gold(gold_dir, capture_id)
        tgn = gold[KEYS].merge(self.score_tgn(graph_dir, capture_id), on=KEYS, how="left", validate="one_to_one")
        if tgn.recon.isna().any():
            raise ValueError("TGN 점수를 받지 못한 Gold 창이 있다")
        scores = {"tgn_recon": tgn.recon.to_numpy(dtype=float), "tail_rarity_v2": self.score_tail(gold),
                  "transformer_v2": self.score_transformer(gold, packet_time_min)}
        parts = [gold[KEYS + ["split"]].assign(model_name=m, score=scores[m],
                                               is_candidate=scores[m] >= self.thresholds[m])
                 for m in MODEL_ORDER]
        return pd.concat(parts, ignore_index=True)

    def build_queue(self, scores, capture_sha):
        """창 점수 → 모델별 사건 큐 → 결합 큐(DD-009). 반환: (결합 사건 목록, 출처, 모델별 큐).

        겹친 사건 처리는 묶음의 결합 설정 overlap_policy를 따른다(없으면 v1의 skip, v2는 merge_windows, DD-018).
        """
        from zeek_ad.evaluation import build_incidents, rank_queue
        from zeek_ad.fusion import fuse

        names = [m["name"] for m in self.fusion["models"]]
        queues = []
        for name in names:
            day = scores[(scores.model_name == name) & (scores.split != "capture_edge")]
            queues.append(rank_queue(build_incidents(day[KEYS + ["score"]].to_dict("records"),
                                                     self.thresholds[name], capture_sha)))
        fused, sources = fuse(queues, names, self.fusion.get("overlap_policy", "skip"))
        return fused, sources, dict(zip(names, queues))

    def predict(self, context, model_input, params=None):
        return pd.concat([self.score_capture(r.capture_id, r.gold_dir, r.graph_dir, r.packet_time_min)
                          for r in model_input.itertuples(index=False)], ignore_index=True)
