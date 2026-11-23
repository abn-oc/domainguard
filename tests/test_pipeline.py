"""Leakage and determinism checks."""

import numpy as np
import pandas as pd
import pytest

from domainguard import config, models


def test_processed_splits_do_not_overlap():
    if not (config.PROCESSED_DIR / "phish_train.pkl").exists():
        pytest.skip("processed data not built yet")
    for prefix in ("phish", "dga"):
        splits = {
            name: set(pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_{name}.pkl")["registered_domain"].astype(str))
            for name in ("train", "val", "test")
        }
        for first in splits:
            for second in splits:
                if first < second:
                    assert not (splits[first] & splits[second]), (prefix, first, second)


def test_simulator_sets_unseen_in_training():
    if not (config.PROCESSED_DIR / "dga_test.pkl").exists():
        pytest.skip("processed data not built yet")
    trained = set()
    for prefix in ("phish", "dga"):
        trained |= set(pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_train.pkl")["registered_domain"].astype(str))
    tested = set()
    for prefix in ("phish", "dga"):
        tested |= set(pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_test.pkl")["registered_domain"].astype(str))
    assert not (trained & tested)


def test_model_determinism_on_tiny_frames(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PROCESSED_DIR", tmp_path)
    rng = np.random.RandomState(0)
    rows = []
    for label in (0, 1):
        for index in range(40):
            rows.append({"domain": f"{'a' if label == 0 else 'x'}{index}zz",
                         "registered_domain": f"d{label}{index}.com",
                         "family": "benign" if label == 0 else "rand_alnum",
                         "source": "tranco" if label == 0 else "generated",
                         "label": label})
    frame = pd.DataFrame(rows)
    frames = {"train": frame, "val": frame, "test": frame}
    first = models.train_model("dga", seed=42, frames=frames, save=False)
    second = models.train_model("dga", seed=42, frames=frames, save=False)
    assert np.array_equal(first["artifact"]["forest"].predict(first["x_test"]),
                          second["artifact"]["forest"].predict(second["x_test"]))
