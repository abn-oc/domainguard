"""Clean, deduplicate and split the downloaded data.

All splits are grouped by registered domain. No domain from the test split
appears in a training split, and no DGA training names are taken from the
benign set.
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

import pandas as pd

from .. import config
from ..dga.generators import generate_all
from ..features import is_free_hosting
from ..normalize import normalize

SPLITS = ("train", "val", "test")
SPLIT_FRACTIONS = (0.70, 0.15, 0.15)


def _lines(path: Path, limit: int | None = None):
    read = 0
    with path.open(encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if limit is not None and read >= limit:
                return
            if line := line.strip():
                read += 1
                yield line


def load_tranco(path: Path, limit: int | None = None) -> tuple[list[tuple[str, str, str]], int]:
    """Return (registered_domain, sld_label, raw) tuples and duplicate count."""
    seen: dict[str, tuple[str, str, str]] = {}
    duplicates = 0
    for line in _lines(path, limit):
        parts = line.split(",", 1)
        raw = parts[-1].strip()
        norm = normalize(raw)
        if not norm.registered_domain or not norm.tld or not norm.sld_label:
            continue
        key = norm.registered_domain
        if key in seen:
            duplicates += 1
            continue
        seen[key] = (key, norm.sld_label, raw)
    return list(seen.values()), duplicates


def load_phishing_links(paths: list[Path], limit: int | None = None) -> tuple[list[dict], int]:
    """Deduplicate on full normalized URL; keep one row per registered domain."""
    seen_urls: set[str] = set()
    by_domain: dict[str, dict] = {}
    duplicates = 0
    for path in paths:
        if not path.exists():
            continue
        for line in _lines(path, limit):
            norm = normalize(line)
            if not norm.host or norm.is_ip_host or not norm.registered_domain:
                continue
            url_key = norm.host + norm.path + ("?" + norm.query if norm.query else "")
            if url_key in seen_urls:
                duplicates += 1
                continue
            seen_urls.add(url_key)
            if norm.registered_domain not in by_domain:
                by_domain[norm.registered_domain] = {
                    "raw_url": line,
                    "registered_domain": norm.registered_domain,
                    "source": path.stem,
                    "is_free_host": int(is_free_hosting(norm.registered_domain)),
                    "label": 1,
                }
    return list(by_domain.values()), duplicates


def grouped_split(rows: list, domain_of, n_per_class: int,
                  seed: int = config.SEED) -> dict[str, list]:
    """Assign whole domain groups to splits near the 70/15/15 targets."""
    groups: dict[str, list] = defaultdict(list)
    for row in rows:
        groups[domain_of(row)].append(row)
    keys = list(groups)
    random.Random(seed).shuffle(keys)
    targets = [int(n_per_class * fraction) for fraction in SPLIT_FRACTIONS]
    targets[-1] = n_per_class - targets[0] - targets[1]
    remaining = list(targets)
    result: dict[str, list] = {split: [] for split in SPLITS}
    for key in keys:
        candidates = [i for i in range(3) if remaining[i] > 0]
        if not candidates:
            break
        # Prefer the split with the most free capacity.
        index = max(candidates, key=lambda i: remaining[i])
        chosen = SPLITS[index]
        result[chosen].extend(groups[key])
        remaining[index] -= len(groups[key])
    return result


def _sample(rows: list, n: int, seed: int) -> list:
    rows = list(rows)
    if len(rows) <= n:
        return rows
    return random.Random(seed).sample(rows, n)


def build(n_per_class: int = config.N_PER_CLASS, seed: int = config.SEED,
          smoke: bool = False) -> dict:
    """Build all processed splits and return build metadata."""
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    if smoke:
        n_per_class = min(n_per_class, 300)
        # Smoke uses real downloaded rows, but only a small prefix of each file
        # so the end-to-end check finishes in under two minutes.
    line_limit = 50_000 if smoke else None

    manifest_path = config.MANIFEST_PATH
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    tranco_file = config.RAW_DIR / "tranco.csv"
    if not tranco_file.exists():
        raise FileNotFoundError("Tranco data missing; run data/download.py --tranco first")

    tranco_rows, tranco_dupes = load_tranco(tranco_file, line_limit)
    tranco_domains = {row[0] for row in tranco_rows}
    tranco_map = grouped_split(tranco_rows, lambda row: row[0], len(tranco_rows), seed)
    split_domains = {
        split: {row[0] for row in rows} for split, rows in tranco_map.items()
    }

    # ---- Phishing side -------------------------------------------------
    link_paths = [config.RAW_DIR / "phishing-links-ACTIVE.txt",
                  config.RAW_DIR / "phishing-domains-ACTIVE.txt",
                  config.RAW_DIR / "openphish-feed.txt"]
    phish_rows, phish_dupes = load_phishing_links(link_paths, line_limit)
    before = len(phish_rows)
    phish_rows = [row for row in phish_rows
                  if row["registered_domain"] not in tranco_domains]
    overlap_removed = before - len(phish_rows)
    phish_split = grouped_split(phish_rows, lambda row: row["registered_domain"],
                                n_per_class, seed)
    free_host_count = sum(row["is_free_host"] for rows in phish_split.values() for row in rows)

    # ---- DGA side ------------------------------------------------------
    benign_tranco_train = [row for row in tranco_map["train"]]
    benign_dga_rows = [
        {"domain": sld, "registered_domain": registered, "family": "benign",
         "source": "tranco", "label": 0}
        for registered, sld, _raw in benign_tranco_train
    ]
    dga_rows, collisions = generate_all(n_per_class, seed, excluded={r[1] for r in benign_tranco_train})
    generated = [
        {"domain": name, "registered_domain": name, "family": family,
         "source": "generated", "label": 1}
        for name, family in dga_rows
    ]
    dga_benign_split = grouped_split(
        benign_dga_rows, lambda row: row["registered_domain"], n_per_class, seed
    )
    dga_mal_split = grouped_split(
        generated, lambda row: row["registered_domain"], n_per_class, seed
    )

    meta = {
        "n_per_class_requested": n_per_class,
        "seed": seed,
        "smoke": smoke,
        "tranco_list_id": manifest.get("tranco", {}).get("list_id"),
        "tranco_rows": len(tranco_rows),
        "tranco_duplicates_removed": tranco_dupes,
        "phishing_rows_before_cleaning": before + overlap_removed,
        "phishing_duplicates_removed": phish_dupes,
        "phishing_benign_overlap_removed": overlap_removed,
        "phishing_free_host_rows": free_host_count,
        "dga_generated_rows": len(generated),
        "dga_collisions_discarded": collisions,
        "actual_sizes": {},
    }

    for split in SPLITS:
        phish = _sample(phish_split[split], n_per_class, seed)
        # Keep the classes balanced within each split: if the phishing source
        # has fewer unique domains than requested, use the same number of
        # benign rows rather than inventing additional malicious data.
        benign = _sample(
            [{"raw_url": raw, "registered_domain": registered, "source": "tranco",
              "is_free_host": 0, "label": 0}
             for registered, _sld, raw in tranco_map[split]],
            len(phish), seed,
        )
        phish_df = pd.DataFrame(benign + phish)
        phish_df.to_pickle(config.PROCESSED_DIR / f"phish_{split}.pkl")

        dga_benign = _sample(dga_benign_split[split], n_per_class, seed)
        dga_mal = _sample(dga_mal_split[split], n_per_class, seed)
        dga_df = pd.DataFrame(dga_benign + dga_mal)
        dga_df.to_pickle(config.PROCESSED_DIR / f"dga_{split}.pkl")

        meta["actual_sizes"][split] = {
            "phish_benign": len(benign), "phish_malicious": len(phish),
            "dga_benign": len(dga_benign), "dga_malicious": len(dga_mal),
        }
        print(f"  {split}: phishing {len(benign)}+{len(phish)}, DGA {len(dga_benign)}+{len(dga_mal)}")

    (config.PROCESSED_DIR / "build_meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8"
    )
    # Assert the grouping invariant promised by the handout.
    for split in SPLITS:
        df = pd.read_pickle(config.PROCESSED_DIR / f"phish_{split}.pkl")
        other = set()
        for other_split in SPLITS:
            if other_split != split:
                other |= set(pd.read_pickle(config.PROCESSED_DIR / f"phish_{other_split}.pkl")["registered_domain"])
        assert not (set(df["registered_domain"]) & other), "phishing domain leaked across splits"
    return meta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-per-class", type=int, default=config.N_PER_CLASS)
    parser.add_argument("--seed", type=int, default=config.SEED)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args(argv)
    build(args.n_per_class, args.seed, args.smoke)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
