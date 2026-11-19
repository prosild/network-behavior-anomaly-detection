"""통계 기준선과 Isolation Forest (설계 6.1절). 둘 다 월요일 학습 창으로만 적합한다.

점수는 클수록 이상하다. 공격 확률이 아니다.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from zeek_ad.gold_features import FEATURES, RATIOS

# 비율은 이미 0~1이라 그대로 두고, 나머지 비음수 값은 log1p로 줄인다(설계 3.3절).
# 특징 목록을 넘기지 않으면 v1 18개를 쓴다. v2의 로그 특징은 모두 개수·최댓값이라 log1p 대상이다.
LOG_FEATURES = [f for f in FEATURES if f not in RATIOS]


class Preprocessor:
    """학습 구간 통계로만 적합하는 전처리. 결측은 학습 중앙값으로 채운다.

    결측 표시는 duration_missing_ratio가 맡는다. 창의 모든 연결이 결측이면 그 값이 1이다.
    """

    def __init__(self, features=FEATURES):
        self.features = list(features)
        self.log_features = [f for f in self.features if f not in RATIOS]

    def fit(self, train):
        x = self._log(train)
        self.medians_ = x.median()
        return self

    def transform(self, df):
        x = self._log(df).fillna(self.medians_)
        # 역할 범주는 공통 모델의 입력에 넣는다(설계 3.3절).
        x["role_responder"] = (df["role"] == "responder").astype(float)
        return x

    def params(self):
        return {"log1p": self.log_features, "impute_median": self.medians_.round(6).to_dict()}

    def _log(self, df):
        x = df[self.features].astype(float).copy()
        x[self.log_features] = np.log1p(x[self.log_features])
        return x


class TailRarity:
    """특징별 학습 경험분포에서 양쪽 꼬리의 희귀도를 구하고, 가장 큰 값을 창 점수로 쓴다.

    p_low = (학습값 <= x 개수 + 1) / (n + 1), p_high = (학습값 >= x 개수 + 1) / (n + 1).
    희귀도 = -log(min(p_low, p_high)). 같음(<=, >=)을 포함하므로 이산값 동률은 덜 희귀하게 센다.
    상수 특징은 학습값과 같으면 0, 다르면 최대 희귀도 log(n+1)가 된다. 결측 특징은 점수에서 뺀다.
    역할 범주는 점수 계산에 쓰지 않는다.
    """

    def __init__(self, features=FEATURES):
        self.features = list(features)

    def fit(self, train):
        self.sorted_ = {f: np.sort(train[f].dropna().to_numpy(dtype=float)) for f in self.features}
        return self

    def score(self, df):
        rarity = pd.DataFrame(index=df.index)
        for f, ref in self.sorted_.items():
            x = df[f].to_numpy(dtype=float)
            n = len(ref)
            le = np.searchsorted(ref, x, side="right")  # 학습값 <= x
            ge = n - np.searchsorted(ref, x, side="left")  # 학습값 >= x
            p = np.minimum(le + 1, ge + 1) / (n + 1)
            r = -np.log(p)
            r[np.isnan(x)] = np.nan
            rarity[f] = r
        return rarity.max(axis=1, skipna=True).to_numpy()


class IForest:
    """두 역할을 함께 학습하는 Isolation Forest 하나. 200 trees, max_samples=min(256, n), seed 42."""

    def __init__(self, n_estimators=200, seed=42):
        self.n_estimators, self.seed = n_estimators, seed

    def fit(self, x_train):
        self.max_samples_ = min(256, len(x_train))
        self.model_ = IsolationForest(n_estimators=self.n_estimators, max_samples=self.max_samples_,
                                      random_state=self.seed).fit(x_train)
        return self

    def score(self, x):
        # score_samples는 작을수록 이상하다. 부호를 바꿔 클수록 이상하게 통일한다.
        # 내장 contamination 판정(predict)은 쓰지 않는다(설계 6.1절).
        return -self.model_.score_samples(x)

    def params(self):
        return {"n_estimators": self.n_estimators, "max_samples": self.max_samples_, "seed": self.seed}
