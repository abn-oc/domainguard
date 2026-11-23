"""Classify DNS queries and rank client machines.

NXDOMAIN rate is displayed only. It is never a classifier feature and never
enters ranking or accuracy numbers.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .. import config, models
from ..normalize import normalize
from .parse import LogParser


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def scan_log(path: str | Path, fmt: str = "auto", min_flags: int = 3,
             threshold_key: str = "threshold_0p1pct",
             dga_model: dict | None = None,
             phish_model: dict | None = None) -> dict:
    """Scan one log and return ranked clients plus report metadata."""
    path = Path(path)
    dga_model = dga_model or models.load_model("dga")
    phish_model = phish_model or models.load_model("phish_host")
    # The scanner uses the strict threshold from each model's own validation set.
    dga_threshold = dga_model["thresholds"][threshold_key]
    phish_threshold = phish_model["thresholds"][threshold_key]

    parser = LogParser(path, fmt)
    clients: dict[str, dict] = defaultdict(lambda: {
        "domains": {}, "queries": 0, "nxdomain": 0,
    })
    for record in parser.records():
        client = str(record.get("id.orig_h", ""))
        norm = normalize(str(record.get("query", "")))
        if not client or not norm.registered_domain or norm.is_ip_host:
            continue
        info = clients[client]
        info["queries"] += 1
        if str(record.get("rcode_name", "")).upper() == "NXDOMAIN":
            info["nxdomain"] += 1
        domain = norm.registered_domain
        entry = info["domains"].setdefault(domain, {
            "sld": norm.sld_label, "count": 0, "nxdomain": 0,
        })
        entry["count"] += 1
        if str(record.get("rcode_name", "")).upper() == "NXDOMAIN":
            entry["nxdomain"] += 1

    all_domains = sorted({domain for info in clients.values() for domain in info["domains"]})
    domain_slds: dict[str, str] = {}
    for info in clients.values():
        for domain, entry in info["domains"].items():
            domain_slds.setdefault(domain, entry["sld"])
    if all_domains:
        dga_scores = dict(zip(
            all_domains, models.score(dga_model, [domain_slds[d] for d in all_domains])
        ))
        phish_scores = dict(zip(all_domains, models.score(phish_model, all_domains)))
    else:
        dga_scores, phish_scores = {}, {}

    flagged_domains: list[str] = []
    ranked: list[dict] = []
    for client, info in clients.items():
        flagged = {}
        for domain, entry in info["domains"].items():
            if dga_scores[domain] >= dga_threshold or phish_scores[domain] >= phish_threshold:
                flagged[domain] = entry
                if domain not in flagged_domains:
                    flagged_domains.append(domain)
        total_unique = len(info["domains"])
        share = len(flagged) / total_unique if total_unique else 0.0
        flagged_queries = sum(entry["count"] for entry in flagged.values())
        row = {
            "client": client,
            "flagged_domains": len(flagged),
            "flagged_queries": flagged_queries,
            "flagged_share": round(share, 4),
            "nxdomain_rate": round(info["nxdomain"] / info["queries"], 4) if info["queries"] else 0.0,
            "total_unique_domains": total_unique,
            "total_queries": info["queries"],
        }
        if len(flagged) >= min_flags:
            row["domains"] = sorted(flagged)
            ranked.append(row)
    ranked.sort(key=lambda row: (row["flagged_domains"], row["flagged_share"]), reverse=True)

    report = {
        "input_file": str(path).replace("\\", "/"),
        "sha256": _sha256(path),
        "scanned_utc": datetime.now(timezone.utc).isoformat(),
        "format": parser.format,
        "malformed_lines": parser.malformed,
        "total_clients": len(clients),
        "min_flags": min_flags,
        "thresholds": {
            "dga": dga_threshold,
            "phish_host": phish_threshold,
            "threshold_key": threshold_key,
        },
        "ranked_clients": ranked,
        "flagged_domains": sorted(flagged_domains),
    }
    return report


def write_report(report: dict, out_dir: str | Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "scan_report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return path


def format_table(report: dict) -> str:
    rows = report["ranked_clients"]
    header = f"{'CLIENT':<18} {'FLAGGED':>7} {'QUERIES':>7} {'SHARE':>7} {'NXDOMAIN':>9}"
    lines = [header, "-" * len(header)]
    for row in rows:
        lines.append(
            f"{row['client']:<18} {row['flagged_domains']:>7} "
            f"{row['flagged_queries']:>7} {row['flagged_share']:>7.3f} "
            f"{row['nxdomain_rate']:>9.3f}"
        )
    if not rows:
        lines.append("(no client reached the minimum evidence threshold)")
    return "\n".join(lines)
