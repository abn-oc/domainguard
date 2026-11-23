"""Minimal, stateless Flask demo: one URL checker and one DNS log scanner.

Security defaults: debug off, loopback bind, autoescape on, no |safe,
20 MB upload cap, per-session CSRF token, no file persistence.
"""

from __future__ import annotations

import hmac
import os
import secrets
import tempfile
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for

from .. import config, models
from ..cli import DISPLAY_THRESHOLD
from ..normalize import defang, normalize
from ..scanner.dns_scan import scan_log

ALLOWED_UPLOAD_SUFFIXES = {".log", ".txt", ".csv", ".json"}


def _csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def _csrf_ok() -> bool:
    expected = session.get("csrf_token", "")
    provided = request.form.get("csrf_token", "")
    return bool(expected) and hmac.compare_digest(expected, provided)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("DOMAINGUARD_SECRET", secrets.token_hex(32))
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES
    app.jinja_env.autoescape = True

    @app.get("/")
    def index():
        return redirect(url_for("check"))

    @app.route("/check", methods=["GET", "POST"])
    def check():
        result = None
        error = None
        submitted = request.form.get("value", "") if request.method == "POST" else ""
        if request.method == "POST":
            if not _csrf_ok():
                return "Invalid CSRF token", 400
            value = request.form.get("value", "")
            norm = normalize(value)
            if not norm.host:
                error = "Enter a URL or domain name."
            else:
                result = {
                    "input": defang(norm.raw),
                    "host": defang(norm.host),
                    "registered_domain": defang(norm.registered_domain),
                    "sld_label": norm.sld_label,
                    "verdicts": [],
                }
                for name in ("phish_host", "dga"):
                    model = models.load_model(name)
                    raw = norm.sld_label if name == "dga" else norm.host
                    score = float(models.score(model, [raw])[0])
                    threshold = float(model["thresholds"][DISPLAY_THRESHOLD])
                    result["verdicts"].append({
                        "name": name,
                        "flagged": score >= threshold,
                        "score": f"{score:.4f}",
                        "threshold": f"{threshold:.4f}",
                    })
                result["features"] = models.features_for_visualisation(
                    models.load_model("phish_host"), norm.host
                )
        return render_template("check.html", token=_csrf_token(), result=result,
                               error=error, submitted=submitted)

    @app.get("/scan")
    def scan_form():
        return render_template("scan.html", token=_csrf_token(), report=None,
                               error=None, submitted="")

    @app.post("/scan")
    def scan_upload():
        if not _csrf_ok():
            return "Invalid CSRF token", 400
        uploaded = request.files.get("log")
        if uploaded is None or not uploaded.filename:
            return render_template("scan.html", token=_csrf_token(), report=None,
                                   error="Choose a log file first."), 400
        if Path(uploaded.filename).suffix.lower() not in ALLOWED_UPLOAD_SUFFIXES:
            return render_template("scan.html", token=_csrf_token(), report=None,
                                   error="Unsupported file type."), 400
        # Temporary file is deleted before the response is returned.
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "upload.log"
            uploaded.save(path)
            report = scan_log(path)
        return render_template("scan.html", token=_csrf_token(), report=report, error=None)

    @app.get("/scan/sample")
    def scan_sample():
        if not config.SAMPLE_LOG.exists():
            return render_template("scan.html", token=_csrf_token(), report=None,
                                   error="Sample log is missing; run domainguard simulate --sample."), 404
        report = scan_log(config.SAMPLE_LOG)
        return render_template("scan.html", token=_csrf_token(), report=report, error=None)

    return app


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args(argv)
    create_app().run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
