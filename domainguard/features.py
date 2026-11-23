"""Shared numeric feature extraction with named, fixed-order feature groups.

The same code serves the phishing models (URL in, host and optional path
features out) and the DGA model (second-level label in, character-shape
features out). Feature order is part of the saved model contract.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from difflib import SequenceMatcher
from functools import lru_cache
from pathlib import Path

import numpy as np

from .config import KEYWORDS, KEYWORD_TO_FEATURE, FREE_HOSTING_DOMAINS
from .normalize import Normalized, normalize

VOWELS = set("aeiou")
HEX = re.compile(r"^[0-9a-f]{8,}$")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
LONG_TOKEN = re.compile(r"[A-Za-z0-9]{20,}")

# Fixed groups and fixed order. Adding a feature here requires retraining.
PHISH_FEATURES: dict[str, list[str]] = {
    "length": [
        "len_host", "len_sld", "len_subdomain", "len_path", "len_query",
        "n_dots", "n_hyphens", "n_digits_host", "subdomain_depth",
    ],
    "charstats": [
        "digit_ratio", "letter_ratio", "vowel_ratio", "vowel_consonant_ratio",
        "entropy_sld", "entropy_host", "entropy_path",
        "max_consonant_run", "max_digit_run",
    ],
    "keywords": [
        "kw_login", "kw_secure", "kw_account", "kw_verify", "kw_update",
        "kw_bank", "kw_signin", "kw_pay", "kw_count",
    ],
    "brand": ["brand_in_wrong_place", "brand_in_sld_not_official", "brand_fuzzy_score"],
    "ngram": ["ngram_loglik_sld", "ngram_loglik_host"],
    "subdomain": ["sub_has_ip_like", "sub_has_hex", "sub_len_max_label"],
    "path": [
        "path_depth", "path_has_ext_php_html", "path_has_ip",
        "path_has_long_token", "query_n_params", "query_entropy",
    ],
    "flags": ["has_userinfo", "has_punycode", "is_ip_host", "has_port"],
}

DGA_FEATURES: dict[str, list[str]] = {
    "length": ["len_sld", "n_digits_sld", "n_hyphens_sld"],
    "charstats": [
        "digit_ratio", "letter_ratio", "vowel_ratio", "vowel_consonant_ratio",
        "entropy_sld", "max_consonant_run", "max_digit_run",
    ],
    "ngram": ["ngram_loglik_sld"],
}

PHISH_GROUPS = tuple(PHISH_FEATURES)
PHISH_HOST_GROUPS = tuple(g for g in PHISH_FEATURES if g != "path")
DGA_GROUPS = tuple(DGA_FEATURES)


@lru_cache(maxsize=1)
def _brands() -> dict[str, tuple[str, ...]]:
    path = Path(__file__).with_name("brands.json")
    with path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    return {token: tuple(domains) for token, domains in raw.items()}


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


@lru_cache(maxsize=1)
def _brand_items() -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple(_brands().items())


@lru_cache(maxsize=1_000_000)
def _brand_fuzzy(sld: str, registered: str) -> float:
    """Cached max brand similarity for one (sld, registered domain) pair.

    SequenceMatcher is relatively slow and the same domains are evaluated by
    every model, so cache the exact result. The cache does not change values.
    """
    best = 0.0
    for token, official in _brand_items():
        if registered in official:
            continue
        if sld:
            best = max(best, SequenceMatcher(None, sld, token).ratio())
    return best


def _max_run(text: str, members: set[str]) -> int:
    best = current = 0
    for char in text:
        current = current + 1 if char in members else 0
        best = max(best, current)
    return best


def _ratios(sld: str) -> dict[str, float]:
    length = len(sld)
    digits = sum(ch.isdigit() for ch in sld)
    letters = sum(ch.isalpha() for ch in sld)
    vowels = sum(ch in VOWELS for ch in sld)
    consonants = letters - vowels
    return {
        "digit_ratio": digits / length if length else 0.0,
        "letter_ratio": letters / length if length else 0.0,
        "vowel_ratio": vowels / length if length else 0.0,
        "vowel_consonant_ratio": vowels / consonants if consonants else 0.0,
        "entropy_sld": entropy(sld),
        "max_consonant_run": _max_run(sld, set("bcdfghjklmnpqrstvwxyz")),
        "max_digit_run": _max_run(sld, set("0123456789")),
    }


def _charstats(norm: Normalized) -> dict[str, float]:
    values = _ratios(norm.sld_label)
    values["entropy_host"] = entropy(norm.host)
    values["entropy_path"] = entropy(norm.path)
    return values


def _brand_features(norm: Normalized) -> dict[str, float]:
    registered = norm.registered_domain
    search_blob = (norm.subdomain + " " + norm.path + " " + norm.query).lower()
    sld = norm.sld_label.lower()
    values = {
        "brand_in_wrong_place": 0.0,
        "brand_in_sld_not_official": 0.0,
        "brand_fuzzy_score": 0.0,
    }
    for token, official in _brand_items():
        if registered in official:
            continue
        if token in search_blob:
            values["brand_in_wrong_place"] = 1.0
        if token in sld:
            values["brand_in_sld_not_official"] = 1.0
    values["brand_fuzzy_score"] = _brand_fuzzy(sld, registered)
    return values


class FeatureExtractor:
    """Feature extractor for the two phishing models."""

    def __init__(self, groups=PHISH_HOST_GROUPS, ngram_sld=None, ngram_host=None):
        self.groups = tuple(groups)
        self.ngram_sld = ngram_sld
        self.ngram_host = ngram_host
        self.feature_names = [
            name for group in self.groups for name in PHISH_FEATURES[group]
        ]

    def extract_one(self, raw: str, sld_score: float | None = None,
                    host_score: float | None = None,
                    norm: Normalized | None = None) -> list[float]:
        norm = norm if norm is not None else normalize(raw)
        sld = norm.sld_label.lower()
        host = norm.host.lower()
        vals: dict[str, float] = {
            "len_host": len(host),
            "len_sld": len(sld),
            "len_subdomain": len(norm.subdomain),
            "len_path": len(norm.path),
            "len_query": len(norm.query),
            "n_dots": norm.host.count("."),
            "n_hyphens": norm.host.count("-"),
            "n_digits_host": sum(ch.isdigit() for ch in norm.host),
            "subdomain_depth": len([x for x in norm.subdomain.split(".") if x]),
            "ngram_loglik_sld": (sld_score if sld_score is not None else
                                 (self.ngram_sld.score(sld) if self.ngram_sld else 0.0)),
            "ngram_loglik_host": (host_score if host_score is not None else
                                  (self.ngram_host.score(host) if self.ngram_host else 0.0)),
            "sub_has_ip_like": float(bool(IPV4.search(norm.subdomain))),
            "sub_has_hex": float(any(HEX.match(label) for label in norm.subdomain.split("."))),
            "sub_len_max_label": max((len(x) for x in norm.subdomain.split(".")), default=0),
            "path_depth": len([x for x in norm.path.split("/") if x]),
            "path_has_ext_php_html": float(norm.path.lower().endswith((".php", ".html", ".htm"))),
            "path_has_ip": float(bool(IPV4.search(norm.path))),
            "path_has_long_token": float(bool(LONG_TOKEN.search(norm.path))),
            "query_n_params": len([x for x in norm.query.split("&") if x]) if norm.query else 0,
            "query_entropy": entropy(norm.query),
            "has_userinfo": float(norm.has_userinfo),
            "has_punycode": float(norm.has_punycode),
            "is_ip_host": float(norm.is_ip_host),
            "has_port": float(norm.has_port),
        }
        vals.update(_charstats(norm))
        blob = (norm.host + " " + norm.path + " " + norm.query).lower()
        for token in KEYWORDS:
            vals[KEYWORD_TO_FEATURE[token]] = float(token in blob)
        vals["kw_count"] = sum(vals[KEYWORD_TO_FEATURE[token]] for token in KEYWORDS)
        vals.update(_brand_features(norm))
        return [float(vals[name]) for name in self.feature_names]

    def extract_many(self, values, sld_scores=None, host_scores=None,
                     norms=None) -> np.ndarray:
        rows = [
            self.extract_one(
                str(value),
                None if sld_scores is None else float(sld_scores[i]),
                None if host_scores is None else float(host_scores[i]),
                None if norms is None else norms[i],
            )
            for i, value in enumerate(values)
        ]
        return np.asarray(rows, dtype=np.float64).reshape(len(rows), len(self.feature_names))


class DgaFeatureExtractor:
    """Feature extractor for the DGA model (second-level label only)."""

    def __init__(self, groups=DGA_GROUPS, ngram_sld=None):
        self.groups = tuple(groups)
        self.ngram_sld = ngram_sld
        self.feature_names = [
            name for group in self.groups for name in DGA_FEATURES[group]
        ]

    def extract_one(self, name: str, sld_score: float | None = None) -> list[float]:
        sld = str(name).lower()
        vals: dict[str, float] = {
            "len_sld": len(sld),
            "n_digits_sld": sum(ch.isdigit() for ch in sld),
            "n_hyphens_sld": sld.count("-"),
            "ngram_loglik_sld": (sld_score if sld_score is not None else
                                 (self.ngram_sld.score(sld) if self.ngram_sld else 0.0)),
        }
        vals.update(_ratios(sld))
        return [float(vals[key]) for key in self.feature_names]

    def extract_many(self, values, sld_scores=None) -> np.ndarray:
        rows = [
            self.extract_one(
                str(value), None if sld_scores is None else float(sld_scores[i])
            )
            for i, value in enumerate(values)
        ]
        return np.asarray(rows, dtype=np.float64).reshape(len(rows), len(self.feature_names))


def is_free_hosting(registered_domain: str) -> bool:
    """True when the registered domain is a known free host / site builder."""
    return registered_domain.lower() in FREE_HOSTING_DOMAINS
