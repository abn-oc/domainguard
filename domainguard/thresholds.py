"""FPR-based thresholds, chosen only on benign validation scores."""

from __future__ import annotations

import numpy as np


def threshold_for_fpr(benign_scores, target_fpr: float) -> float:
    """Score such that about target_fpr of benign validation scores are >= it."""
    scores = np.asarray(benign_scores, dtype=np.float64)
    if scores.size == 0:
        raise ValueError("no benign validation scores available")
    quantile = 1.0 - target_fpr
    return float(np.quantile(scores, quantile, method="higher"))


def select_thresholds(benign_scores) -> dict[str, float]:
    """Return the two fixed thresholds and the FPR actually achieved."""
    scores = np.asarray(benign_scores, dtype=np.float64)
    result = {}
    for label, target in (("1pct", 0.01), ("0p1pct", 0.001)):
        threshold = threshold_for_fpr(scores, target)
        achieved = float(np.mean(scores >= threshold))
        result[f"threshold_{label}"] = threshold
        result[f"validation_fpr_{label}"] = achieved
    return result


def flag(scores, threshold: float) -> np.ndarray:
    """Decision rule used everywhere: score >= threshold means flagged."""
    return np.asarray(scores) >= threshold
