"""Transformer 입력 시퀀스(DD-002). 자산·역할마다 직전 K개 5분 칸으로 다음 창의 특징을 예측한다.

칸 하나는 토큰 하나다. 토큰 = 표준화 특징 18개 + role_responder + is_inactive + is_outside.
- 활동 있는 칸: 그 창의 Gold 행을 전처리한 값.
- 활동 없는 칸(캡처 안, Gold 행 없음): 특징 0, is_inactive=1.
- 캡처 밖 칸(캡처 첫 칸보다 앞): 특징 0, is_outside=1.
정의는 configs/models/transformer.v1.json을 따른다.
"""

import numpy as np

from zeek_ad.gold_features import FEATURES

SERIES = ["capture_id", "asset_id", "role"]
MARKER_COLUMNS = ["role_responder", "is_inactive", "is_outside"]
TOKEN_COLUMNS = FEATURES + MARKER_COLUMNS  # v1 기준. v2는 Gold manifest의 특징 목록 + MARKER_COLUMNS


class Scaler:
    """학습 행의 평균·표준편차로 표준화한다. 표준편차 0인 특징은 1로 나눈다(값이 0이 된다)."""

    def fit(self, x):
        self.mean_ = x.mean(axis=0)
        std = x.std(axis=0)
        self.std_ = np.where(std > 0, std, 1.0)
        return self

    def transform(self, x):
        return (x - self.mean_) / self.std_

    def params(self, names):
        return {n: {"mean": float(m), "std": float(s)} for n, m, s in zip(names, self.mean_, self.std_)}


def build_sequences(keys, features, role_responder, first_slot, window_seconds, k):
    """모든 행에 대해 (직전 k칸 토큰, 그 행의 특징)을 만든다.

    keys: 행마다 (capture_id, asset_id, role, window_start) 목록.
    features: (행 수, 18) 표준화 특징. role_responder: (행 수,) 0/1.
    first_slot: 캡처별 첫 칸의 window_start.
    반환: x (행 수, k, 21), y (행 수, 18). x[:, -1]이 대상 바로 앞 칸이다.
    """
    n, f = features.shape
    row_of = {key: i for i, key in enumerate(keys)}
    if len(row_of) != n:
        raise ValueError("키가 중복된다")
    x = np.zeros((n, k, f + 3), dtype=np.float32)
    for i, (cap, asset, role, start) in enumerate(keys):
        x[i, :, f] = role_responder[i]
        for pos in range(k):
            # pos 0이 가장 오래된 칸, pos k-1이 바로 앞 칸.
            slot = start - (k - pos) * window_seconds
            if slot < first_slot[cap]:
                x[i, pos, f + 2] = 1.0
            elif (cap, asset, role, slot) in row_of:
                x[i, pos, :f] = features[row_of[(cap, asset, role, slot)]]
            else:
                x[i, pos, f + 1] = 1.0
    return x, features.astype(np.float32)
