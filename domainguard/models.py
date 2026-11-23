"""Train, save, load and score the three random-forest detectors."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier

from . import config
from .features import (
    DGA_FEATURES,
    DGA_GROUPS,
    PHISH_FEATURES,
    PHISH_GROUPS,
    DgaFeatureExtractor,
    FeatureExtractor,
)
from .ngram import CharTrigram, out_of_fold_scores
from .normalize import normalize
from .thresholds import select_thresholds

MODEL_TYPES = ("phish_host", "phish_full", "dga")


def _manifest_hash() -> str:
    if not config.MANIFEST_PATH.exists():
        return "none"
    return hashlib.sha256(config.MANIFEST_PATH.read_bytes()).hexdigest()


def _model_path(name: str, seed: int) -> Path:
    return config.MODELS_DIR / f"{name}_seed{seed}.joblib"


def _groups_for(name: str) -> tuple[str, ...]:
    if name == "phish_host":
        return tuple(g for g in PHISH_FEATURES if g != "path")
    if name == "phish_full":
        return PHISH_GROUPS
    if name == "dga":
        return DGA_GROUPS
    raise ValueError(f"unknown model: {name}")


def _feature_names(groups, name: str) -> list[str]:
    table = DGA_FEATURES if name == "dga" else PHISH_FEATURES
    return [feature for group in groups for feature in table[group]]


def _oof_features(name: str, train_df: pd.DataFrame, val_df: pd.DataFrame,
                  test_df: pd.DataFrame, groups, seed: int, forest):
    """Build train/val/test matrices, with train n-gram scores out of fold."""
    if name == "dga":
        train_values = train_df["domain"].tolist()
        val_values = val_df["domain"].tolist()
        test_values = test_df["domain"].tolist()
        benign_indices = [i for i, label in enumerate(train_df["label"]) if label == 0]
        benign_names = [str(train_values[i]) for i in benign_indices]
        oof = out_of_fold_scores(benign_names, seed=seed)
        full = CharTrigram.fit(benign_names)
        sld_train = [0.0] * len(train_values)
        benign_index_set = set(benign_indices)
        for position, row_index in enumerate(benign_indices):
            sld_train[row_index] = oof[position]
        for i, value in enumerate(train_values):
            if i not in benign_index_set:
                sld_train[i] = full.score(value)
        extractor = DgaFeatureExtractor(groups=groups, ngram_sld=full)
        x_train = extractor.extract_many(train_values, sld_scores=sld_train)
        x_val = extractor.extract_many(val_values)
        x_test = extractor.extract_many(test_values)
        return extractor, x_train, x_val, x_test, {"sld": full, "host": None}

    train_values = train_df["raw_url"].tolist()
    val_values = val_df["raw_url"].tolist()
    test_values = test_df["raw_url"].tolist()
    norms = [normalize(value) for value in train_values]
    benign_indices = [i for i, label in enumerate(train_df["label"]) if label == 0]
    benign_slds = [norms[i].sld_label for i in benign_indices]
    benign_hosts = [norms[i].host for i in benign_indices]
    oof_sld = out_of_fold_scores(benign_slds, seed=seed)
    oof_host = out_of_fold_scores(benign_hosts, seed=seed)
    full_sld = CharTrigram.fit(benign_slds)
    full_host = CharTrigram.fit(benign_hosts)
    sld_train = [full_sld.score(norm.sld_label) for norm in norms]
    host_train = [full_host.score(norm.host) for norm in norms]
    for position, row_index in enumerate(benign_indices):
        sld_train[row_index] = oof_sld[position]
        host_train[row_index] = oof_host[position]
    extractor = FeatureExtractor(groups=groups, ngram_sld=full_sld, ngram_host=full_host)
    x_train = extractor.extract_many(train_values, sld_train, host_train, norms)
    x_val = extractor.extract_many(val_values)
    x_test = extractor.extract_many(test_values)
    return extractor, x_train, x_val, x_test, {"sld": full_sld, "host": full_host}


def train_model(name: str, seed: int = config.SEED,
                groups: tuple[str, ...] | None = None,
                save: bool = True, frames: dict[str, pd.DataFrame] | None = None) -> dict:
    """Train one random forest, set thresholds on validation, save artifacts."""
    if name not in MODEL_TYPES:
        raise ValueError(f"unknown model: {name}")
    groups = _groups_for(name) if groups is None else tuple(groups)
    prefix = "phish" if name.startswith("phish") else "dga"
    if frames is None:
        train_df = pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_train.pkl")
        val_df = pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_val.pkl")
        test_df = pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_test.pkl")
    else:
        train_df, val_df, test_df = frames["train"], frames["val"], frames["test"]

    extractor, x_train, x_val, x_test, ngrams = _oof_features(
        name, train_df, val_df, test_df, groups, seed, None
    )
    params = dict(config.RF_PARAMS)
    params["random_state"] = seed
    forest = RandomForestClassifier(**params)
    forest.fit(x_train, train_df["label"].to_numpy())

    val_scores = forest.predict_proba(x_val)[:, 1]
    thresholds = select_thresholds(val_scores[val_df["label"].to_numpy() == 0])
    feature_names = _feature_names(groups, name)

    artifact = {
        "model_type": name,
        "seed": seed,
        "groups": groups,
        "feature_names": feature_names,
        "forest": forest,
        "ngram_sld": ngrams["sld"].to_dict() if ngrams["sld"] else None,
        "ngram_host": ngrams["host"].to_dict() if ngrams["host"] else None,
        "thresholds": thresholds,
    }
    if save:
        config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(artifact, _model_path(name, seed), compress=3)
    sidecar = {
        "model_type": name,
        "feature_names": feature_names,
        "groups": list(groups),
        "thresholds": thresholds,
        "hyperparameters": params,
        "seed": seed,
        "data_manifest_hash": _manifest_hash(),
        "sklearn_version": sklearn.__version__,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "train_rows": len(train_df),
        "validation_rows": len(val_df),
        "test_rows": len(test_df),
    }
    if save:
        _model_path(name, seed).with_suffix(".json").write_text(
            json.dumps(sidecar, indent=2, sort_keys=True), encoding="utf-8"
        )
    print(f"  trained {name} seed={seed}: {x_train.shape}, "
          f"FPR@1%={thresholds['validation_fpr_1pct']:.4f}, "
          f"FPR@0.1%={thresholds['validation_fpr_0p1pct']:.4f}")
    return {"artifact": artifact, "sidecar": sidecar, "x_test": x_test,
            "test_labels": test_df["label"].to_numpy()}


def load_model(name: str, seed: int = config.SEED) -> dict:
    """Load a saved model and rebuild its feature extractor."""
    path = _model_path(name, seed)
    if not path.exists():
        raise FileNotFoundError(f"model not found: {path}; run scripts/train.py first")
    artifact = joblib.load(path)
    ngram_sld = (CharTrigram.from_dict(artifact["ngram_sld"])
                 if artifact.get("ngram_sld") else None)
    ngram_host = (CharTrigram.from_dict(artifact["ngram_host"])
                  if artifact.get("ngram_host") else None)
    if name == "dga":
        extractor = DgaFeatureExtractor(artifact["groups"], ngram_sld)
    else:
        extractor = FeatureExtractor(artifact["groups"], ngram_sld, ngram_host)
    artifact["extractor"] = extractor
    return artifact


def score(model: dict, values) -> np.ndarray:
    """Probability scores for raw URLs (phish models) or labels (DGA model)."""
    values = [str(value) for value in values]
    extractor = model["extractor"]
    if model["model_type"] == "dga":
        features = extractor.extract_many(values)
    else:
        features = extractor.extract_many(values)
    return model["forest"].predict_proba(features)[:, 1]


def features_for_visualisation(model: dict, raw: str) -> list[tuple[str, float]]:
    """Contribution estimates from global forest importances for one input."""
    extractor = model["extractor"]
    vector = extractor.extract_one(str(raw))
    importances = model["forest"].feature_importances_
    pairs = list(zip(model["feature_names"], vector, importances))
    pairs.sort(key=lambda item: item[1] * item[2], reverse=True)
    return [(name, float(value)) for name, value, _importance in pairs[:5]]
