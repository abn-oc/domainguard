"""The scoring path must never touch the network."""

import socket
import urllib.request

import http.client
import pytest
import requests

from domainguard import cli
from domainguard.scanner import dns_scan


def _block(*args, **kwargs):
    raise AssertionError("network access attempted from the scoring path")


def test_check_and_scan_are_offline(tmp_path, monkeypatch):
    monkeypatch.setattr(socket, "socket", _block)
    monkeypatch.setattr(socket, "create_connection", _block)
    monkeypatch.setattr(urllib.request, "urlopen", _block)
    monkeypatch.setattr(requests.sessions.Session, "request", _block)
    monkeypatch.setattr(http.client.HTTPConnection, "request", _block)

    fake = {"thresholds": {"threshold_1pct": 0.5, "threshold_0p1pct": 0.9}}
    monkeypatch.setattr(cli.models, "load_model", lambda name: fake)
    monkeypatch.setattr(cli.models, "score", lambda model, values: [0.1 for _ in values])
    monkeypatch.setattr(cli.models, "features_for_visualisation", lambda model, raw: [])
    monkeypatch.setattr(dns_scan.models, "load_model", lambda name: fake)
    monkeypatch.setattr(dns_scan.models, "score", lambda model, values: [0.1 for _ in values])

    assert cli.main(["check", "example.com", "--json"]) == 0
    log = tmp_path / "dns.log"
    log.write_text("#fields\tts\tid.orig_h\tquery\trcode_name\n1\t10.0.0.1\ta.example\tNOERROR\n")
    assert cli.main(["scan", str(log), "--out", str(tmp_path / "out")]) == 0
