"""TGN 이벤트 그래프 이상탐지 모델(DD-007). practice/04_tgn_pytorch.ipynb에서 사용자가 작성한 코드다.

노드는 IP, 엣지는 연결 하나다. 연결을 보기 직전의 노드 표현으로 그 연결의 엣지 정보를 복원하고,
복원 오차(recon)와 메모리 이동량(latent_shift)을 이상 점수로 쓴다.
설정은 configs/models/tgn.v1.json, 입력은 scripts/build_tgn_dataset.py의 출력이다.

노트북에서 전역 변수(N_CAT, CAT_SIZES, memory 등)를 쓰던 부분만 인자·속성으로 바꿨다. 계산은 같다.
재현성을 위해 CPU에서만 돌린다(설정 training.device).
"""

import json

import numpy as np
import pandas as pd
import torch
from torch import nn
import torch.nn.functional as F
from torch_geometric.data import TemporalData
from torch_geometric.loader import TemporalDataLoader
from torch_geometric.nn import TransformerConv
from torch_geometric.nn.models.tgn import LastAggregator, LastNeighborLoader, TGNMemory

KEYS = ["capture_id", "asset_id", "role", "window_start"]


def split_raw(raw, n_cat, n_hist):
    # msg 54열 → (범주 id (B, 15), history id (B, 12), 수치 (B, 27))
    return (raw[:, :n_cat].long(), raw[:, n_cat:n_cat + n_hist].long(), raw[:, n_cat + n_hist:])


class EdgeEncoder(nn.Module):
    # 엣지 정보 54열 → 벡터 (B, out_dim)

    def __init__(self, cat_sizes, hist_vocab, hist_len, n_num, cat_dim, hist_dim, num_dim, out_dim):
        super().__init__()
        self.out_dim = out_dim
        self.n_cat, self.hist_len = len(cat_sizes), hist_len
        self.cats = nn.ModuleList([nn.Embedding(n, cat_dim) for n in cat_sizes])
        self.hist = nn.Embedding(hist_vocab, hist_dim, padding_idx=0)
        self.num = nn.Linear(n_num, num_dim)
        self.out = nn.Linear(len(cat_sizes) * cat_dim + hist_len * hist_dim + num_dim, out_dim)

    def forward(self, raw):
        cat, hist, num = split_raw(raw, self.n_cat, self.hist_len)
        parts = [emb(cat[:, i]) for i, emb in enumerate(self.cats)]
        parts.append(self.hist(hist).flatten(1))
        parts.append(self.num(num))

        return torch.relu(self.out(torch.cat(parts, dim=-1)))


class EdgeMessage(nn.Module):
    # TGN 메시지 = concat(출발 메모리, 도착 메모리, 엣지 벡터, 시간 인코딩)

    def __init__(self, memory_dim, time_dim, make_edge):
        super().__init__()
        self.edge = make_edge()
        self.out_channels = 2 * memory_dim + self.edge.out_dim + time_dim

    def forward(self, z_src, z_dst, raw_msg, t_enc):
        return torch.cat([z_src, z_dst, self.edge(raw_msg), t_enc], dim=-1)


class GraphEmbedding(nn.Module):
    # 메모리 + 노드 특징 + 최근 이웃 attention → z (n, out_dim)

    def __init__(self, memory_dim, node_dim, time_enc, out_dim, heads, dropout, make_edge):
        super().__init__()
        self.time_enc = time_enc
        self.node = nn.Linear(node_dim, memory_dim)
        self.edge = make_edge()
        edge_dim = time_enc.out_channels + self.edge.out_dim
        self.conv = TransformerConv(memory_dim, out_dim // heads, heads=heads, dropout=dropout, edge_dim=edge_dim)

    def forward(self, memory, node_feat, last_update, edge_index, t, raw_msg):
        # memory (n, 64), node_feat (n, 20), last_update (n,), edge_index (2, m), t (m,), raw_msg (m, 54)
        x = memory + self.node(node_feat)
        rel_t = (last_update[edge_index[0]] - t).to(x.dtype)
        edge_attr = torch.cat([self.time_enc(rel_t), self.edge(raw_msg)], dim=1)

        return self.conv(x, edge_index, edge_attr)


class EdgeDecoder(nn.Module):
    # concat(z_출발, z_도착) → 그 연결의 엣지 정보 예측

    def __init__(self, emb_dim, hidden, cat_sizes, hist_vocab, hist_len, n_num):
        super().__init__()
        self.hist_len, self.hist_vocab = hist_len, hist_vocab
        self.mlp = nn.Sequential(nn.Linear(2 * emb_dim, hidden), nn.ReLU())
        self.cat_heads = nn.ModuleList([nn.Linear(hidden, n) for n in cat_sizes])
        self.hist_head = nn.Linear(hidden, hist_len * hist_vocab)
        self.num_head = nn.Linear(hidden, n_num)

    def forward(self, z_src, z_dst):
        h = self.mlp(torch.cat([z_src, z_dst], dim=-1))
        cat_logits = [head(h) for head in self.cat_heads]
        hist_logits = self.hist_head(h).view(-1, self.hist_len, self.hist_vocab)

        return cat_logits, hist_logits, self.num_head(h)


def event_loss(out, raw):
    # 반환: (B,) 이벤트별 복원 손실
    cat_logits, hist_logits, num_pred = out
    cat, hist, num = split_raw(raw, len(cat_logits), hist_logits.shape[1])
    ce_cat = torch.stack([F.cross_entropy(logits, cat[:, i], reduction="none")
                          for i, logits in enumerate(cat_logits)], dim=1).mean(dim=1)
    ce_hist = F.cross_entropy(hist_logits.transpose(1, 2), hist, reduction="none").mean(dim=1)
    mse = ((num_pred - num) ** 2).mean(dim=1)

    return ce_cat + ce_hist + mse


def weighted_mean(loss, w):
    return (loss * w).sum() / w.sum()


def latent_shift(before, after):
    # before, after: (B, memory_dim). 반환: (B,)
    return (after - before).norm(dim=1)


def load_graph(graph_dir):
    """시간 그래프를 읽어 (TemporalData, 노드 특징, index 표, encoding)을 돌려준다."""
    d = np.load(graph_dir / "events.npz")
    msg = torch.cat([torch.from_numpy(d["cat"]).float(), torch.from_numpy(d["hist"]).float(),
                     torch.from_numpy(d["num"])], dim=1)
    data = TemporalData(src=torch.from_numpy(d["src"]), dst=torch.from_numpy(d["dst"]),
                        t=torch.from_numpy(d["t"]), msg=msg, w=torch.from_numpy(d["dns_weight"]))
    index = pd.read_parquet(graph_dir / "index.parquet")
    index["capture_id"] = index["capture_id"].astype(str)
    encoding = json.loads((graph_dir / "encoding.json").read_text(encoding="utf-8"))
    return data, torch.from_numpy(d["node_x"]), index, encoding


class EventTGN(nn.Module):
    """메모리·임베딩·디코더와 이웃 표를 묶는다. 노트북의 build_tgn, forward_batch, update_graph에 해당한다.

    parameter는 노드 수와 무관하다. 노드 수는 메모리·이웃 표(상태)의 크기만 정한다.
    """

    def __init__(self, config, encoding, num_nodes, node_dim, raw_msg_dim):
        super().__init__()
        m, e = config["model"], config["model"]["edge_encoder"]
        cat_sizes = [encoding["vocab_sizes"][c] for c in encoding["categorical"]]
        n_hist = config["data"]["history_max_len"]
        n_num = len(encoding["numeric"])

        def make_edge():
            return EdgeEncoder(cat_sizes, encoding["history_vocab_size"], n_hist, n_num, e["categorical_dim"],
                               e["history_dim"], e["numeric_dim"], e["out_dim"])

        # 생성 순서가 노트북 build_tgn과 같아야 같은 seed에서 같은 초기값이 나온다.
        torch.manual_seed(config["training"]["seed"])
        self.memory = TGNMemory(num_nodes, raw_msg_dim, m["memory_dim"], m["time_dim"],
                                EdgeMessage(m["memory_dim"], m["time_dim"], make_edge), LastAggregator())
        self.gnn = GraphEmbedding(m["memory_dim"], node_dim, self.memory.time_enc, m["embedding"]["out_dim"],
                                  m["embedding"]["heads"], m["embedding"]["dropout"], make_edge)
        self.decoder = EdgeDecoder(m["embedding"]["out_dim"], m["decoder"]["hidden"], cat_sizes,
                                   encoding["history_vocab_size"], n_hist, n_num)
        self.neighbors = LastNeighborLoader(num_nodes, size=m["embedding"]["neighbors"])
        self.assoc = torch.empty(num_nodes, dtype=torch.long)

    def reset(self, start):
        # 메모리 0, 이웃 표 비우기. 이웃 연결 번호(e_id)는 data에서의 위치라 구간 시작으로 맞춘다.
        self.memory.reset_state()
        self.neighbors.reset_state()
        self.neighbors.cur_e_id = start

    def forward_batch(self, batch, data, node_x):
        # 갱신 전 상태로 이번 batch 연결들의 엣지 정보를 예측하고 이벤트별 손실을 돌려준다.
        n_id, edge_index, e_id = self.neighbors(batch.n_id)
        self.assoc[n_id] = torch.arange(n_id.size(0))
        mem, last_update = self.memory(n_id)
        z = self.gnn(mem, node_x[n_id], last_update, edge_index, data.t[e_id], data.msg[e_id])
        out = self.decoder(z[self.assoc[batch.src]], z[self.assoc[batch.dst]])
        return event_loss(out, batch.msg)

    def update_graph(self, batch):
        self.memory.update_state(batch.src, batch.dst, batch.t, batch.msg)
        self.neighbors.insert(batch.src, batch.dst)

    def parameter_state(self):
        """체크포인트용. 학습한 parameter만 담는다(메모리 버퍼는 상태라 뺀다)."""
        return {k: v.detach().clone() for k, v in self.named_parameters()}

    def load_parameter_state(self, state):
        missing, unexpected = self.load_state_dict(state, strict=False)
        # 빠져도 되는 것: 메모리 버퍼(상태)와 같은 parameter의 다른 이름(gnn.time_enc = memory.time_enc).
        allowed = set(self.state_dict()) - set(dict(self.named_parameters()))
        if unexpected or set(missing) - allowed:
            raise ValueError(f"체크포인트가 모델 구조와 다르다: missing={missing} unexpected={unexpected}")


def train_epoch(tgn, data, node_x, start, end, batch_size, optimizer):
    # 노트북 [9]와 같다. epoch마다 메모리·이웃 표를 비우고 train 처음부터 다시 흘린다.
    tgn.train()
    tgn.reset(start)
    total, weight = 0.0, 0.0
    for batch in TemporalDataLoader(data[start:end], batch_size=batch_size):
        optimizer.zero_grad()
        loss_each = tgn.forward_batch(batch, data, node_x)
        loss = weighted_mean(loss_each, batch.w)
        tgn.update_graph(batch)
        loss.backward()
        optimizer.step()
        tgn.memory.detach()
        total += (loss_each.detach() * batch.w).sum().item()
        weight += batch.w.sum().item()
    return total / weight


def score_capture(tgn, data, node_x, start, end, batch_size):
    # [start, end) 구간(한 캡처)을 흘리며 이벤트마다 (복원 오차, 출발 이동량, 도착 이동량)을 매긴다.
    tgn.eval()
    tgn.reset(start)
    recon, shift_src, shift_dst = [], [], []
    with torch.no_grad():
        for batch in TemporalDataLoader(data[start:end], batch_size=batch_size):
            recon.append(tgn.forward_batch(batch, data, node_x).numpy())
            before_src = tgn.memory.memory[batch.src].clone()
            before_dst = tgn.memory.memory[batch.dst].clone()
            tgn.update_graph(batch)
            shift_src.append(latent_shift(before_src, tgn.memory.memory[batch.src]).numpy())
            shift_dst.append(latent_shift(before_dst, tgn.memory.memory[batch.dst]).numpy())
    return np.concatenate(recon), np.concatenate(shift_src), np.concatenate(shift_dst)


def window_scores(rows, recon, shift_src, shift_dst, exclude_peer=None):
    """연결 점수를 (캡처, 자산, 역할, 5분 창)의 최댓값으로 모은다.

    자산이 출발이면 originator 창(이동량은 출발 노드 값), 도착이면 responder 창(도착 노드 값)이다.
    exclude_peer: 상대가 이 주소인 연결을 뺀다(NAT 제외 진단). 그러면 연결이 모두 빠진 창은 결과에 없다.
    """
    orig_mask = rows.orig_scored.to_numpy()
    resp_mask = rows.resp_scored.to_numpy()
    if exclude_peer is not None:
        orig_mask = orig_mask & (rows.resp_h != exclude_peer).to_numpy()
        resp_mask = resp_mask & (rows.orig_h != exclude_peer).to_numpy()
    orig = rows.assign(asset_id=rows.orig_h, role="originator", recon=recon, shift=shift_src)[orig_mask]
    resp = rows.assign(asset_id=rows.resp_h, role="responder", recon=recon, shift=shift_dst)[resp_mask]
    both = pd.concat([orig, resp])
    return both.groupby(KEYS + ["split"]).agg(recon=("recon", "max"), shift=("shift", "max")).reset_index()
