import unittest

import numpy as np

from zeek_ad.sequences import Scaler, build_sequences

# 규칙 확인용 가짜 예제다. 특징은 2개로 줄였다(토큰 = 2 + 3 = 5차원).
W = 300
FIRST = {"cap": 0}


def run(keys, k=3):
    feats = np.array([[float(i + 1), -float(i + 1)] for i in range(len(keys))])
    role = np.array([1.0 if key[2] == "responder" else 0.0 for key in keys])
    return build_sequences(keys, feats, role, FIRST, W, k)


class BuildSequencesTest(unittest.TestCase):
    def test_previous_windows_inactive_and_outside(self):
        # 0, 300, 900 칸에 활동. 600 칸은 비어 있다.
        keys = [("cap", "a", "originator", 0), ("cap", "a", "originator", 300), ("cap", "a", "originator", 900)]
        x, y = run(keys)
        # 900의 맥락은 [0, 300, 600] 칸이다.
        np.testing.assert_array_equal(x[2, 0], [1, -1, 0, 0, 0])
        np.testing.assert_array_equal(x[2, 1], [2, -2, 0, 0, 0])
        np.testing.assert_array_equal(x[2, 2], [0, 0, 0, 1, 0])  # 활동 없음
        # 0의 맥락은 모두 캡처 앞이다.
        np.testing.assert_array_equal(x[0, :, 4], [1, 1, 1])
        np.testing.assert_array_equal(y[2], [3, -3])  # 대상은 자기 창의 특징

    def test_series_do_not_mix(self):
        # 같은 칸이라도 다른 역할·자산의 창은 맥락에 들어가지 않는다.
        keys = [("cap", "a", "originator", 0), ("cap", "a", "responder", 300), ("cap", "b", "originator", 300)]
        x, _ = run(keys, k=1)
        np.testing.assert_array_equal(x[1, 0], [0, 0, 1, 1, 0])  # role_responder=1, 활동 없음
        np.testing.assert_array_equal(x[2, 0], [0, 0, 0, 1, 0])

    def test_duplicate_key_is_error(self):
        with self.assertRaises(ValueError):
            run([("cap", "a", "originator", 0)] * 2)


class ScalerTest(unittest.TestCase):
    def test_constant_feature_becomes_zero(self):
        x = np.array([[1.0, 5.0], [3.0, 5.0]])
        z = Scaler().fit(x).transform(x)
        np.testing.assert_allclose(z, [[-1, 0], [1, 0]])


if __name__ == "__main__":
    unittest.main()
