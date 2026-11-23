import numpy as np

from domainguard.thresholds import flag, select_thresholds, threshold_for_fpr


def test_threshold_toy_array():
    scores = np.linspace(0, 1, 1001)
    threshold = threshold_for_fpr(scores, 0.01)
    assert 0.98 < threshold < 1.001
    assert np.mean(scores >= threshold) <= 0.02


def test_select_thresholds_and_flag():
    scores = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
    result = select_thresholds(scores)
    assert result["threshold_1pct"] >= result["threshold_0p1pct"]
    assert 0 <= result["validation_fpr_1pct"] <= 0.2
    flags = flag([0.0, 1.0], result["threshold_1pct"])
    assert flags.tolist() == [False, True]
