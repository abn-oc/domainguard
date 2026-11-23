import re

import pytest

from domainguard.web.app import create_app


@pytest.fixture
def fake_models(monkeypatch):
    from domainguard.web import app as app_module

    model = {
        "thresholds": {"threshold_1pct": 0.5, "threshold_0p1pct": 0.9},
        "feature_names": ["len_sld"],
        "groups": ("length",),
    }
    monkeypatch.setattr(app_module.models, "load_model", lambda name: model)
    monkeypatch.setattr(app_module.models, "score", lambda model, values: [0.7 for _ in values])
    monkeypatch.setattr(
        app_module.models, "features_for_visualisation",
        lambda model, raw: [("len_sld", 7.0)],
    )
    return model


@pytest.fixture
def client(fake_models):
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _token(client, path="/check"):
    page = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert match
    return match.group(1)


def test_routes(client):
    assert client.get("/").status_code == 302
    assert client.get("/check").status_code == 200
    assert client.get("/scan").status_code == 200


def test_check_post_and_flagged(client):
    token = _token(client)
    response = client.post("/check", data={"csrf_token": token, "value": "evil.example.com"})
    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "evil[.]example[.]com" in text
    assert "FLAGGED" in text


def test_escaping(client):
    token = _token(client)
    payload = "<script>alert(1)</script>"
    response = client.post("/check", data={"csrf_token": token, "value": payload})
    text = response.get_data(as_text=True)
    assert payload not in text
    assert "&lt;script&gt;" in text


def test_csrf_rejected(client):
    response = client.post("/check", data={"csrf_token": "wrong", "value": "example.com"})
    assert response.status_code == 400


def test_sample_scan_route(client, tmp_path, monkeypatch):
    from domainguard.web import app as app_module
    from domainguard.scanner import dns_scan

    fake = {"thresholds": {"threshold_0p1pct": 0.9}}
    monkeypatch.setattr(dns_scan.models, "load_model", lambda name: fake)
    monkeypatch.setattr(dns_scan.models, "score", lambda model, values: [0.01 for _ in values])

    log = tmp_path / "sample_dns.log"
    log.write_text("#fields\tts\tid.orig_h\tquery\trcode_name\n1\t10.0.0.1\ta.example\tNOERROR\n")
    monkeypatch.setattr(app_module.config, "SAMPLE_LOG", log)
    response = client.get("/scan/sample")
    assert response.status_code == 200
    assert "Ranked clients" in response.get_data(as_text=True)
