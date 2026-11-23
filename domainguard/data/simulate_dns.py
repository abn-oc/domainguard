"""Generate a labelled DNS log from the held-out test partition only.

The log itself has no labels, so the scanner cannot see the answers. The
separate label file is never read by the scanner.
"""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

import pandas as pd

from .. import config

CLIENT_TYPES = (
    "benign", "benign_cdn_heavy", "infected_dga", "infected_phish",
)


def _test_rows():
    phish_test = pd.read_pickle(config.PROCESSED_DIR / "phish_test.pkl")
    dga_test = pd.read_pickle(config.PROCESSED_DIR / "dga_test.pkl")
    return phish_test, dga_test


def _leakage_check(benign: set[str], malicious: set[str]) -> None:
    """Simulator names must never have appeared in a training partition."""
    trained: set[str] = set()
    for prefix in ("phish", "dga"):
        frame = pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_train.pkl")
        trained |= set(frame["registered_domain"].astype(str))
    overlap = (benign | malicious) & trained
    assert not overlap, f"simulator names leaked into training: {list(overlap)[:5]}"


def simulate(seed: int = config.SEED, out_dir: Path | None = None,
             sample: bool = False, n_clients: int = 12,
             benign_per_client: int = 25, malicious_per_client: int = 8) -> dict:
    """Write a Zeek TSV log plus a separate label CSV; return a summary."""
    out_dir = Path(out_dir) if out_dir else (config.SAMPLES_DIR if sample else config.SIM_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    phish_test, dga_test = _test_rows()

    benign_phish = [str(x) for x in phish_test.loc[phish_test.label == 0, "registered_domain"].unique()]
    benign_dga = [str(x) for x in dga_test.loc[dga_test.label == 0, "registered_domain"].unique()]
    malicious_dga = [str(x) for x in dga_test.loc[dga_test.label == 1, "domain"].unique()]
    malicious_phish = [str(x) for x in phish_test.loc[phish_test.label == 1, "registered_domain"].unique()]
    benign_pool = sorted(set(benign_phish) | set(benign_dga))
    benign_set, malicious_set = set(benign_pool), set(malicious_dga) | set(malicious_phish)
    _leakage_check(benign_set, malicious_set)

    lines = ["#separator \\x09", "#fields\tts\tid.orig_h\tquery\trcode_name"]
    labels = []
    timestamp = 1_700_000_000.0
    for index in range(n_clients):
        client_type = CLIENT_TYPES[index % len(CLIENT_TYPES)]
        client_ip = f"10.0.{index // 250}.{index % 250 + 1}"
        benign_names = rng.sample(benign_pool, min(benign_per_client, len(benign_pool)))
        queries: list[str] = []
        for name in benign_names:
            if client_type == "benign_cdn_heavy" and rng.random() < 0.6:
                prefix = "cdn-" + "".join(rng.choice("abcdef0123456789") for _ in range(8))
                queries.append(f"{prefix}.{name}")
            else:
                queries.append(name)
        malicious: list[str] = []
        if client_type == "infected_dga":
            malicious = rng.sample(malicious_dga, min(malicious_per_client, len(malicious_dga)))
            queries.extend(f"{name}.example" for name in malicious)
        elif client_type == "infected_phish":
            malicious = rng.sample(malicious_phish, min(malicious_per_client, len(malicious_phish)))
            queries.extend(malicious)
        rng.shuffle(queries)
        for query in queries:
            rcode = "NXDOMAIN" if query.split(".")[0] in malicious and rng.random() < 0.3 else "NOERROR"
            timestamp += 0.1
            lines.append(f"{timestamp:.1f}\t{client_ip}\t{query}\t{rcode}")
        label = "infected" if client_type.startswith("infected") else "benign"
        labels.append([client_ip, label, client_type, " ".join(malicious)])

    log_path = out_dir / "sample_dns.log" if sample else out_dir / "sim_dns.log"
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    summary = {
        "seed": seed,
        "sample": sample,
        "log": str(log_path),
        "clients": n_clients,
        "queries": len(lines) - 2,
        "benign_domains": len(benign_pool),
        "malicious_dga_domains": len(malicious_dga),
        "malicious_phish_domains": len(malicious_phish),
    }
    if not sample:
        label_path = out_dir / "sim_labels.csv"
        with label_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["client", "label", "client_type", "malicious_domains"])
            writer.writerows(labels)
        summary["labels"] = str(label_path)
        (out_dir / "sim_summary.json").write_text(
            __import__("json").dumps(summary, indent=2), encoding="utf-8"
        )
    print("  " + ", ".join(f"{k}={v}" for k, v in summary.items()))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=config.SEED)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--sample", action="store_true",
                        help="write the small committed web-demo log")
    parser.add_argument("--clients", type=int, default=12)
    parser.add_argument("--malicious-per-client", type=int, default=8)
    args = parser.parse_args(argv)
    simulate(args.seed, args.out, args.sample, n_clients=args.clients,
             malicious_per_client=args.malicious_per_client)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
