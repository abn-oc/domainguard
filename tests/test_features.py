import math

import numpy as np

from domainguard.features import (
    DGA_FEATURES,
    PHISH_FEATURES,
    DgaFeatureExtractor,
    FeatureExtractor,
    entropy,
    is_free_hosting,
)


def test_feature_names_stable():
    host = FeatureExtractor()
    assert host.feature_names == [n for group in ("length", "charstats", "keywords", "brand", "ngram", "subdomain", "flags") for n in PHISH_FEATURES[group]]
    full = FeatureExtractor(groups=tuple(PHISH_FEATURES))
    assert len(full.feature_names) == sum(len(v) for v in PHISH_FEATURES.values())


def test_no_nan_or_infinity():
    samples = ["", "example.com", "http://a.b.example.co.uk/x.php?a=1&b=2", "192.168.0.1", "https://xn--bcher-kva.example/pay"]
    matrix = FeatureExtractor(groups=tuple(PHISH_FEATURES)).extract_many(samples)
    assert np.isfinite(matrix).all()
    assert matrix.shape == (len(samples), len(FeatureExtractor(groups=tuple(PHISH_FEATURES)).feature_names))


def test_dga_features_finite():
    dga = DgaFeatureExtractor()
    matrix = dga.extract_many(["k3q9zvt0ra2m", "", "sunny-river2"])
    assert np.isfinite(matrix).all()
    assert matrix.shape == (3, sum(len(v) for v in DGA_FEATURES.values()))


def test_entropy():
    assert entropy("") == 0.0
    assert entropy("aaaa") == 0.0
    assert math.isclose(entropy("ab"), 1.0)


def test_free_hosting():
    assert is_free_hosting("blogspot.com")
    assert not is_free_hosting("example.com")
