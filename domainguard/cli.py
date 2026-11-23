"""Command-line interface: check, scan, simulate and evaluate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import config, models
from .data.simulate_dns import simulate
from .normalize import defang, normalize
from .scanner import dns_scan

DISPLAY_THRESHOLD = "threshold_1pct"


def _flag_line(model_name: str, score: float, threshold: float) -> str:
    verdict = "FLAGGED" if score >= threshold else "benign"
    return f"  {model_name:<11} {verdict:<8} score={score:.4f} threshold={threshold:.4f}"


def check(value: str, model_names=("phish_host", "dga"), as_json: bool = False) -> int:
    norm = normalize(value)
    if not norm.host:
        message = {"error": "input is not a URL or domain"}
        print(json.dumps(message) if as_json else message["error"])
        return 2
    loaded = {name: models.load_model(name) for name in model_names}
    scores = {}
    flags = {}
    payload: dict = {
        "input_defanged": defang(norm.raw),
        "host_defanged": defang(norm.host),
        "registered_domain": defang(norm.registered_domain),
        "sld_label": norm.sld_label,
        "verdicts": {},
    }
    for name, model in loaded.items():
        raw = norm.sld_label if name == "dga" else norm.host
        score = float(models.score(model, [raw])[0])
        threshold = float(model["thresholds"][DISPLAY_THRESHOLD])
        scores[name] = score
        flags[name] = score >= threshold
        payload["verdicts"][name] = {
            "score": score, "threshold": threshold,
            "threshold_name": DISPLAY_THRESHOLD, "flagged": bool(flags[name]),
        }
    payload["top_features"] = [
        {"feature": feature, "value": value}
        for feature, value in models.features_for_visualisation(
            loaded[model_names[0]], norm.sld_label if model_names[0] == "dga" else norm.host
        )
    ]
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        print("normalized:", payload["input_defanged"])
        for name in model_names:
            print(_flag_line(name, scores[name], loaded[name]["thresholds"][DISPLAY_THRESHOLD]))
        print("top features (global importances):")
        for item in payload["top_features"]:
            print(f"  {item['feature']:<28} {item['value']:.2f}")
    return 1 if any(flags.values()) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="domainguard", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    check_parser = sub.add_parser("check", help="score one URL or domain")
    check_parser.add_argument("value")
    check_parser.add_argument("--json", action="store_true")
    check_parser.add_argument("--model", choices=["phish_host", "phish_full", "dga", "all"],
                              default="all")

    scan_parser = sub.add_parser("scan", help="scan a DNS log")
    scan_parser.add_argument("log")
    scan_parser.add_argument("--format", choices=["zeek", "csv", "json", "auto"], default="auto")
    scan_parser.add_argument("--min-flags", type=int, default=3)
    scan_parser.add_argument("--out", type=Path, default=config.DATA_DIR / "scan")

    sim_parser = sub.add_parser("simulate", help="generate a labelled DNS log")
    sim_parser.add_argument("--seed", type=int, default=config.SEED)
    sim_parser.add_argument("--out", type=Path, default=None)

    eval_parser = sub.add_parser("evaluate", help="generate docs/results.md")
    eval_parser.add_argument("--quick", action="store_true")

    args = parser.parse_args(argv)
    if args.command == "check":
        names = ("phish_host", "dga") if args.model == "all" else (args.model,)
        return check(args.value, names, args.json)
    if args.command == "scan":
        report = dns_scan.scan_log(args.log, args.format, args.min_flags)
        print(dns_scan.format_table(report))
        path = dns_scan.write_report(report, args.out)
        print(f"wrote {path}")
        return 0
    if args.command == "simulate":
        simulate(args.seed, args.out)
        return 0
    if args.command == "evaluate":
        from scripts.evaluate import main as evaluate_main
        return evaluate_main(["--quick"] if args.quick else [])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
