"""Regression tests for bugs found while building and running the pipeline.

Each test here protects a concrete failure that was observed during the build:
an ignored package directory, a missing manifest in smoke clones, a wrong
artifact key in the evaluation script, and the feature-cache optimisation that
had to preserve exact values.
"""

from __future__ import annotations

import json
import subprocess
from difflib import SequenceMatcher
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from domainguard import cli, config
from domainguard.data import build
from domainguard.evasion.rewrite import KINDS, rewrite
from domainguard.features import _brand_features, _brand_items
from domainguard.normalize import normalize
from scripts import evaluate, make_report


def _reference_brand_features(norm) -> dict[str, float]:
    """Slow but literal implementation used as the cache oracle."""
    registered = norm.registered_domain
    blob = (norm.subdomain + " " + norm.path + " " + norm.query).lower()
    sld = norm.sld_label.lower()
    values = {
        "brand_in_wrong_place": 0.0,
        "brand_in_sld_not_official": 0.0,
        "brand_fuzzy_score": 0.0,
    }
    best = 0.0
    for token, official in _brand_items():
        if registered in official:
            continue
        if token in blob:
            values["brand_in_wrong_place"] = 1.0
        if token in sld:
            values["brand_in_sld_not_official"] = 1.0
        if sld:
            best = max(best, SequenceMatcher(None, sld, token).ratio())
    values["brand_fuzzy_score"] = best
    return values


def test_brand_fuzzy_cache_matches_literal_implementation():
    urls = (
        "http://paypa1-secure.com/login",
        "http://example.co.uk/a?b=1",
        "http://login.bank-of-america.com/verify",
        "not a url at all",
    )
    for raw in urls:
        norm = normalize(raw)
        expected = _reference_brand_features(norm)
        assert _brand_features(norm) == expected
        # Second call exercises the cache; values must be identical.
        assert _brand_features(norm) == expected


def test_rewrite_transforms_are_fixed_string_edits():
    url = "http://Example.com/Login?a=1"
    expected = (
        "http://example.com/Login?a=1",
        "http://EXAMPLE.COM/Login?a=1",
        "http://login.example.com/Login?a=1",
        "http://Example.com/Login?a=1/index.html",
        "http://exa-mple.com/Login?a=1",
        "http://example.c0m/Login?a=1",
    )
    assert tuple(rewrite(url, kind) for kind in KINDS) == expected
    assert rewrite("", "case") == ""  # no host means no transformation
    with pytest.raises(ValueError):
        rewrite(url, "unknown")


def test_train_model_returns_documented_result_contract(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PROCESSED_DIR", tmp_path)
    rows = []
    for label in (0, 1):
        for index in range(20):
            rows.append({
                "domain": f"{'a' if label == 0 else 'x'}{index}zz",
                "registered_domain": f"d{label}{index}.com",
                "family": "benign" if label == 0 else "rand_alnum",
                "source": "tranco" if label == 0 else "generated",
                "label": label,
            })
    frame = pd.DataFrame(rows)
    result = evaluate.models.train_model(
        "dga", seed=42, frames={"train": frame, "val": frame, "test": frame}, save=False
    )
    assert set(("artifact", "sidecar", "x_test", "test_labels")) <= set(result)
    assert "forest" in result["artifact"]
    assert result["x_test"].shape == (40, 11)
    assert result["test_labels"].shape == (40,)


def test_build_smoke_reads_only_limited_lines(tmp_path, monkeypatch):
    raw = tmp_path / "raw"
    processed = tmp_path / "processed"
    raw.mkdir()
    (raw / "tranco.csv").write_text(
        "".join(f"{i},name{i}.com\n" for i in range(100)), encoding="utf-8"
    )
    (raw / "phishing-links-ACTIVE.txt").write_text(
        "".join(f"http://phish{i}.com/login\n" for i in range(100)), encoding="utf-8"
    )
    monkeypatch.setattr(config, "RAW_DIR", raw)
    monkeypatch.setattr(config, "PROCESSED_DIR", processed)
    monkeypatch.setattr(config, "MANIFEST_PATH", tmp_path / "missing_manifest.json")
    monkeypatch.setattr(build, "SMOKE_LINE_LIMIT", 10)

    meta = build.build(smoke=True, n_per_class=10, seed=42)
    assert meta["tranco_rows"] == 10
    assert meta["smoke"] is True
    phish_train = pd.read_pickle(processed / "phish_train.pkl")
    assert len(phish_train) <= 20  # balanced 10 per class requested
    assert set(phish_train["label"]) == {0, 1}


def test_evaluate_manifest_is_optional(tmp_path, monkeypatch):
    missing = tmp_path / "missing.json"
    monkeypatch.setattr(config, "MANIFEST_PATH", missing)
    assert evaluate._load_manifest() == {}
    missing.write_text(json.dumps({"tranco": {"list_id": "test"}}), encoding="utf-8")
    assert evaluate._load_manifest() == {"tranco": {"list_id": "test"}}


def test_make_report_requires_scanner_section(tmp_path, monkeypatch):
    results_dir = tmp_path / "docs"
    figures_dir = results_dir / "figures"
    figures_dir.mkdir(parents=True)
    for name in ("a.png", "b.png", "c.png", "d.png", "e.png"):
        (figures_dir / name).write_bytes(b"png")
    monkeypatch.setattr(config, "RESULTS_DIR", results_dir)
    monkeypatch.setattr(config, "FIGURES_DIR", figures_dir)

    markers = ["Main metrics", "Ablations", "Prevalence-aware",
               "Leave-one-family-out", "External real-data test", "Evasion tests"]
    (results_dir / "results.md").write_text("\n".join(markers), encoding="utf-8")
    with pytest.raises(RuntimeError, match="Scanner on simulated"):
        make_report.main([])

    with (results_dir / "results.md").open("a", encoding="utf-8") as handle:
        handle.write("\nScanner on simulated DNS traffic\n")
    assert make_report.main([]) == 0


def test_gitignore_keeps_package_data_but_ignores_downloads():
    text = (config.ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/data/" in text
    assert "\ndata/\n" not in text

    git_dir = config.ROOT / ".git"
    if not git_dir.exists():
        pytest.skip("not a git checkout")
    package_module = subprocess.run(
        ["git", "check-ignore", "-q", "domainguard/data/build.py"],
        cwd=config.ROOT, capture_output=True,
    )
    assert package_module.returncode != 0, "package module must not be ignored"
    raw_data = subprocess.run(
        ["git", "check-ignore", "-q", "data/raw/tranco.csv"],
        cwd=config.ROOT, capture_output=True,
    )
    assert raw_data.returncode == 0, "downloaded data must be ignored"


def test_cli_exit_codes(monkeypatch):
    fake = {"thresholds": {"threshold_1pct": 0.5, "threshold_0p1pct": 0.9}}
    monkeypatch.setattr(cli.models, "load_model", lambda name: fake)
    monkeypatch.setattr(
        cli.models, "score",
        lambda model, values: [0.9 if "phish" in str(values[0]) else 0.1],
    )
    monkeypatch.setattr(cli.models, "features_for_visualisation", lambda model, raw: [])

    assert cli.main(["check", "http://benign.com", "--json"]) == 0
    assert cli.main(["check", "http://phish.example", "--json"]) == 1
    assert cli.main(["check", "hxxps://bad[.]example/login", "--json"]) == 2


def test_committed_sample_log_is_small():
    if not config.SAMPLE_LOG.exists():
        pytest.skip("sample log not generated yet")
    assert config.SAMPLE_LOG.stat().st_size < 1_000_000
    header = config.SAMPLE_LOG.read_text(encoding="utf-8").splitlines()[:5]
    assert any(line.startswith("#fields") for line in header)


def test_scanner_uses_strict_threshold_even_when_1pct_is_low(tmp_path, monkeypatch):
    from domainguard.scanner import dns_scan

    log = tmp_path / "dns.log"
    log.write_text(
        "#fields\tts\tid.orig_h\tquery\trcode_name\n"
        "1\t10.0.0.1\tone.example\tNOERROR\n"
        "2\t10.0.0.1\ttwo.example\tNOERROR\n"
        "3\t10.0.0.1\tthree.example\tNOERROR\n",
        encoding="utf-8",
    )
    fake = {"thresholds": {"threshold_1pct": 0.1, "threshold_0p1pct": 0.8}}
    monkeypatch.setattr(dns_scan.models, "load_model", lambda name: fake)
    monkeypatch.setattr(dns_scan.models, "score", lambda model, values: [0.5] * len(values))
    report = dns_scan.scan_log(log, min_flags=1)
    assert report["thresholds"]["threshold_key"] == "threshold_0p1pct"
    assert report["ranked_clients"] == []  # 0.5 clears 1% but not 0.1%
