"""Transformer 이상탐지 모델(DD-002). practice/03_transformer_pytorch.ipynb에서 사용자가 작성한 코드다.

직전 k칸 토큰으로 다음 창의 표준화 특징을 예측하고, 예측 오차를 이상 점수로 쓴다.
설정은 configs/models/transformer.v1.json, 입력은 scripts/build_sequences.py의 출력이다.
"""

import numpy as np
import torch
from torch import nn
from torch.utils.data import Dataset


class WindowSequences(Dataset):
    # mask가 True인 행의 (맥락 x, 대상 y)를 담는다.

    def __init__(self, X, Y, mask):
        self.x = torch.from_numpy(X[mask])
        self.y = torch.from_numpy(Y[mask])

    def __len__(self):
        return len(self.x)

    def __getitem__(self, i):
        return self.x[i], self.y[i]


class WindowTransformer(nn.Module):
    # 직전 k칸 토큰 (B, k, n_in)으로 다음 창 특징 (B, n_out)을 예측한다.

    def __init__(self, n_in, n_out, k, d_model, nhead, num_layers, dim_feedforward, dropout):
        super().__init__()
        self.embed = nn.Linear(n_in, d_model)
        self.pos = nn.Embedding(k, d_model)
        layer = nn.TransformerEncoderLayer(d_model, nhead, dim_feedforward, dropout, batch_first=True)
        self.encoder = nn.TransformerEncoder(layer, num_layers)
        self.head = nn.Linear(d_model, n_out)

    def forward(self, x):
        h = self.embed(x)
        positions = torch.arange(x.shape[1], device=x.device)
        h = h + self.pos(positions)
        h = self.encoder(h)
        h = h[:, -1]
        return self.head(h)


def build_model(config, n_in, n_out):
    """고정 설정으로 모델을 만든다. 학습과 체크포인트 적재가 같은 함수를 써야 구조가 같다."""
    m = config["model"]
    torch.manual_seed(config["training"]["seed"])
    return WindowTransformer(n_in=n_in, n_out=n_out, k=config["sequence"]["context_windows"],
                             d_model=m["d_model"], nhead=m["nhead"], num_layers=m["num_layers"],
                             dim_feedforward=m["dim_feedforward"], dropout=m["dropout"])


def train_one_epoch(model, loader, optimizer, loss_fn, device):
    # 한 epoch 학습하고 표본 평균 loss를 돌려준다.
    model.train()
    total = 0.0
    for xb, yb in loader:
        xb, yb = xb.to(device), yb.to(device)
        optimizer.zero_grad()
        loss = loss_fn(model(xb), yb)
        loss.backward()
        optimizer.step()
        total += loss.item() * len(xb)
    return total / len(loader.dataset)


def evaluate_loss(model, loader, loss_fn, device):
    # parameter를 바꾸지 않고 표본 평균 loss를 돌려준다.
    model.eval()
    total = 0.0
    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            total += loss_fn(model(xb), yb).item() * len(xb)
    return total / len(loader.dataset)


def predict_scores(model, loader, device):
    # 표본마다 18개 특징의 평균 제곱 오차. 클수록 이상하다. loader는 shuffle=False여야 순서가 유지된다.
    model.eval()
    parts = []
    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            parts.append(((model(xb) - yb) ** 2).mean(dim=1).cpu().numpy())
    return np.concatenate(parts)
