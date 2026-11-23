"""Generate docs/results.md and figures from measured test-set runs.

Every number in the report comes from a script run in this file. No results
are hard-coded, and no target is silently replaced by a different dataset.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import platform
import random
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import confusion_matrix, roc_auc_score, roc_curve

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from domainguard import config, models  # noqa: E402
from domainguard.data.simulate_dns import simulate  # noqa: E402
from domainguard.scanner.dns_scan import scan_log  # noqa: E402
from domainguard.dga.evasion_generators import EVASION_FAMILIES, generate_evasion_family  # noqa: E402
from domainguard.dga.generators import FAMILIES, load_words  # noqa: E402
from domainguard.evasion.rewrite import KINDS, rewrite  # noqa: E402
from domainguard.features import DGA_FEATURES, PHISH_FEATURES  # noqa: E402

METRIC_KEYS = ("precision", "recall", "f1", "auc", "fpr", "tp", "fp", "tn", "fn")
THRESHOLDS = ("1pct", "0p1pct")


def metrics(y_true, scores, threshold: float) -> dict:
    y_true = np.asarray(y_true, dtype=int)
    scores = np.asarray(scores, dtype=float)
    predicted = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": precision, "recall": recall, "f1": f1,
        "auc": float(roc_auc_score(y_true, scores)) if len(set(y_true)) > 1 else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def aggregate(rows: list[dict]) -> dict[str, str]:
    result = {}
    for key in METRIC_KEYS:
        values = np.array([row[key] for row in rows], dtype=float)
        result[key] = f"{values.mean():.4f} ± {values.std(ddof=0):.4f}"
    return result


def md_table(headers, rows) -> str:
    lines = [
        "| " + " | ".join(str(h) for h in headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def _load_test_scores(name: str, seed: int):
    prefix = "phish" if name.startswith("phish") else "dga"
    df = pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_test.pkl")
    model = models.load_model(name, seed)
    values = df["domain"] if name == "dga" else df["raw_url"]
    return df, model, models.score(model, values)


def _main_metrics(seeds: list[int], figures: dict) -> tuple[dict, dict]:
    per_seed: dict[str, dict] = {}
    summary: dict[str, dict] = {}
    roc_data = {}
    for name in models.MODEL_TYPES:
        by_threshold: dict[str, list[dict]] = {key: [] for key in THRESHOLDS}
        per_seed[name] = {}
        for seed in seeds:
            df, model, scores = _load_test_scores(name, seed)
            y = df["label"].to_numpy()
            per_seed[name][seed] = {"scores": scores, "labels": y}
            for key in THRESHOLDS:
                threshold_name = f"threshold_{key}"
                row = metrics(y, scores, model["thresholds"][threshold_name])
                row["threshold"] = model["thresholds"][threshold_name]
                row["validation_fpr"] = model["thresholds"][f"validation_fpr_{key}"]
                by_threshold[key].append(row)
        summary[name] = by_threshold
        if seeds:
            data = per_seed[name][seeds[0]]
            roc_data[name] = (data["labels"], data["scores"])
    figures["roc"] = roc_data
    return summary, per_seed


def _figure_roc(roc_data: dict) -> Path:
    fig, ax = plt.subplots(figsize=(6, 5))
    for name, (y, scores) in roc_data.items():
        fpr, tpr, _ = roc_curve(y, scores)
        ax.plot(fpr, tpr, label=f"{name} (AUC={roc_auc_score(y, scores):.3f})")
    ax.plot([0, 1], [0, 1], "k--", alpha=0.4)
    ax.set(xlabel="False positive rate", ylabel="True positive rate", title="Test ROC (seed 42)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    path = config.FIGURES_DIR / "roc.png"
    fig.savefig(path, dpi=130)
    plt.close(fig)
    return path


def _figure_bar(path: Path, labels: list[str], values: list[float],
                title: str, ylabel: str) -> None:
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(labels, values)
    ax.set(title=title, ylabel=ylabel)
    ax.tick_params(axis="x", labelrotation=35)
    for label in ax.get_xticklabels():
        label.set_horizontalalignment("right")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def _ablations(seed: int) -> tuple[list[dict], dict]:
    rows = []
    chart = {}
    for name in ("phish_host", "dga"):
        table = PHISH_FEATURES if name.startswith("phish") else DGA_FEATURES
        full_model = models.load_model(name, seed)
        prefix = "phish" if name.startswith("phish") else "dga"
        test_df = pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_test.pkl")
        full_scores = models.score(full_model, test_df["raw_url"] if name.startswith("phish") else test_df["domain"])
        full_metrics = metrics(test_df["label"], full_scores,
                               full_model["thresholds"]["threshold_1pct"])
        for group in table:
            groups = tuple(g for g in table if g != group)
            result = models.train_model(name, seed, groups=groups, save=False)
            scores = result["forest"].predict_proba(result["x_test"])[:, 1]
            ablated = metrics(result["test_labels"], scores,
                              result["artifact"]["thresholds"]["threshold_1pct"])
            rows.append({
                "model": name, "dropped": group,
                "f1": ablated["f1"], "f1_drop": full_metrics["f1"] - ablated["f1"],
                "fpr": ablated["fpr"], "fpr_change": ablated["fpr"] - full_metrics["fpr"],
            })
            chart[f"{name}\n-{group}"] = full_metrics["f1"] - ablated["f1"]
    return rows, chart


def _prevalence(summary: dict) -> list[dict]:
    rows = []
    for name, by_threshold in summary.items():
        for key in THRESHOLDS:
            f1_recall = float(np.mean([row["recall"] for row in by_threshold[key]]))
            fpr = float(np.mean([row["fpr"] for row in by_threshold[key]]))
            for p in (0.01, 0.001, 0.0001):
                denominator = f1_recall * p + fpr * (1 - p)
                precision = f1_recall * p / denominator if denominator else 0.0
                rows.append({
                    "model": name, "threshold": key, "prevalence": f"{p:.2%}",
                    "precision": f"{precision:.4f}", "recall": f"{f1_recall:.4f}",
                    "fpr": f"{fpr:.4f}",
                })
    return rows


def _leave_one_family_out(full_model: dict, seed: int) -> tuple[list[dict], dict]:
    train = pd.read_pickle(config.PROCESSED_DIR / "dga_train.pkl")
    test = pd.read_pickle(config.PROCESSED_DIR / "dga_test.pkl")
    malicious = train[train.label == 1]
    benign = train[train.label == 0]
    threshold = full_model["thresholds"]["threshold_1pct"]
    benign_test = test[test.label == 0]
    rows = []
    chart = {}
    for family in FAMILIES:
        kept_mal = malicious[malicious.family != family]
        fraction = len(kept_mal) / len(malicious)
        kept_ben = benign.sample(int(len(benign) * fraction), random_state=seed)
        frames = {
            "train": pd.concat([kept_ben, kept_mal], ignore_index=True),
            "val": pd.read_pickle(config.PROCESSED_DIR / "dga_val.pkl"),
            "test": test,
        }
        print(f"  LOFO {family}", flush=True)
        result = models.train_model("dga", seed, frames=frames, save=False)
        held_out = test[(test.label == 1) & (test.family == family)]
        held_scores = result["forest"].predict_proba(result["x_test"])[:, 1]
        held_mask = (test.label == 1) & (test.family == family)
        recall = float(np.mean(held_scores[held_mask.to_numpy()] >= threshold)) if held_mask.any() else 0.0
        benign_mask = (test.label == 0).to_numpy()
        fpr = float(np.mean(held_scores[benign_mask] >= threshold))
        rows.append({
            "held_out": family, "train_rows": len(frames["train"]),
            "held_out_test_rows": len(held_out), "recall": f"{recall:.4f}",
            "benign_fpr": f"{fpr:.4f}", "threshold": f"{threshold:.4f}",
        })
        chart[family] = recall
    rows.append({
        "held_out": "average", "train_rows": "-", "held_out_test_rows": "-",
        "recall": f"{np.mean(list(chart.values())):.4f}", "benign_fpr": "-",
        "threshold": f"{threshold:.4f}",
    })
    return rows, chart


def _external_test(full_model: dict, sample_size: int, seed: int,
                   words: tuple[str, ...],
                   max_source_rows: int | None = None) -> dict:
    """Balanced fixed-seed reservoir sample from the external dataset."""
    path = config.RAW_DIR / "extrahop.json.gz"
    if not path.exists():
        raise FileNotFoundError("ExtraHop file missing; run data/download.py --extrahop")
    cap = sample_size // 2
    reservoirs: dict[str, list[str]] = {"benign": [], "dga": []}
    seen: Counter = Counter()
    rng = random.Random(seed)
    rows_read = 0
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if max_source_rows is not None and rows_read >= max_source_rows:
                break
            if line.startswith("#") or not line.strip():
                continue
            rows_read += 1
            row = json.loads(line)
            label = row.get("threat")
            if label not in reservoirs:
                continue
            seen[label] += 1
            index = seen[label]
            if len(reservoirs[label]) < cap:
                reservoirs[label].append(str(row["domain"]))
            else:
                replacement = rng.randrange(index)
                if replacement < cap:
                    reservoirs[label][replacement] = str(row["domain"])
    domains = reservoirs["benign"] + reservoirs["dga"]
    scores = models.score(full_model, domains)
    threshold = full_model["thresholds"]["threshold_1pct"]
    dga_scores = scores[cap:]
    benign_scores = scores[:cap]
    recall = float(np.mean(dga_scores >= threshold))
    fpr = float(np.mean(benign_scores >= threshold))
    wordset = set(words)
    shape_counts = defaultdict(lambda: [0, 0])  # shape -> [total, flagged]
    for domain, score in zip(reservoirs["benign"], benign_scores):
        shape = "word-like" if domain.lower() in wordset else "random-looking"
        shape_counts[shape][0] += 1
        if score >= threshold:
            shape_counts[shape][1] += 1
    return {
        "sample_size": len(domains), "cap_per_class": cap,
        "source_rows_read": dict(seen), "source_lines_read": rows_read,
        "recall": recall, "fpr": fpr,
        "threshold": threshold, "shape_counts": dict(shape_counts),
    }


def _evasion(phish_model: dict, dga_model: dict, seed: int) -> tuple[list[dict], list[dict], dict]:
    test = pd.read_pickle(config.PROCESSED_DIR / "phish_test.pkl")
    malicious = test[test.label == 1]["raw_url"].tolist()
    sample = random.Random(seed).sample(malicious, min(2000, len(malicious)))
    threshold = phish_model["thresholds"]["threshold_1pct"]
    original = np.mean(models.score(phish_model, sample) >= threshold)
    url_rows = []
    chart = {}
    for kind in KINDS:
        rewritten = [rewrite(url, kind) for url in sample]
        rate = float(np.mean(models.score(phish_model, rewritten) >= threshold))
        url_rows.append({
            "transform": kind, "before": f"{original:.4f}", "after": f"{rate:.4f}",
            "drop": f"{original - rate:.4f}",
        })
        chart[kind] = rate

    dga_threshold = dga_model["thresholds"]["threshold_1pct"]
    dga_rows = []
    for family in EVASION_FAMILIES:
        names = generate_evasion_family(family, 1000, seed)
        recall = float(np.mean(models.score(dga_model, names) >= dga_threshold))
        dga_rows.append({"family": family, "recall": f"{recall:.4f}"})
    return url_rows, dga_rows, chart


def _scanner_evaluation(seed: int) -> dict:
    """Scan a labelled simulated log; all numbers are measured, not assumed."""
    summary = simulate(seed=seed, sample=False, n_clients=40,
                       malicious_per_client=60)
    label_path = Path(summary["labels"])
    labels: dict[str, str] = {}
    truth_domains: set[str] = set()
    with label_path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            labels[row["client"]] = row["label"]
            truth_domains.update(row["malicious_domains"].split())
    report = scan_log(Path(summary["log"]), min_flags=3)
    ranked = {row["client"] for row in report["ranked_clients"]}
    expected = {client for client, label in labels.items() if label == "infected"}
    tp = len(ranked & expected)
    fp = len(ranked - expected)
    fn = len(expected - ranked)
    tn = len(set(labels) - ranked - expected)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    flagged = set(report["flagged_domains"])
    domain_precision = len(flagged & truth_domains) / len(flagged) if flagged else 0.0
    domain_recall = len(flagged & truth_domains) / len(truth_domains) if truth_domains else 0.0
    return {
        "clients": len(labels), "infected_clients": len(expected),
        "ranked_clients": len(ranked), "client_tp": tp, "client_fp": fp,
        "client_fn": fn, "client_tn": tn,
        "client_precision": precision, "client_recall": recall,
        "flagged_domains": len(flagged), "true_malicious_domains": len(truth_domains),
        "domain_precision": domain_precision, "domain_recall": domain_recall,
        "min_flags": report["min_flags"], "threshold_key": report["thresholds"]["threshold_key"],
    }


def _git_hash() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"],
                                       stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return "not available in this run"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true",
                        help="seed 42 only and a smaller external sample")
    args = parser.parse_args(argv)
    started = time.time()
    config.FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    seeds = [config.SEED] if args.quick else list(config.SEEDS)
    build_meta_path = config.PROCESSED_DIR / "build_meta.json"
    if not build_meta_path.exists():
        raise FileNotFoundError("processed data missing; run data/build.py first")
    build_meta = json.loads(build_meta_path.read_text(encoding="utf-8"))
    manifest_path = config.MANIFEST_PATH
    manifest = (json.loads(manifest_path.read_text(encoding="utf-8"))
                if manifest_path.exists() else {})

    # Guardrail: the external dataset must never have entered training.
    for split in ("train", "val", "test"):
        for prefix in ("phish", "dga"):
            sources = set(pd.read_pickle(config.PROCESSED_DIR / f"{prefix}_{split}.pkl")["source"])
            assert not (sources & {"extrahop"}), "ExtraHop used in a processed split"

    print("main metrics", flush=True)
    figures: dict = {}
    summary, per_seed = _main_metrics(seeds, figures)
    _figure_roc(figures["roc"])

    print("ablations", flush=True)
    ablation_rows, ablation_chart = _ablations(config.SEED) if not args.quick else ([], {})
    _figure_bar(config.FIGURES_DIR / "ablation_f1_drop.png",
                list(ablation_chart), list(ablation_chart.values()),
                "F1 lost when a feature group is removed", "F1 drop")

    prevalence_rows = _prevalence(summary)

    print("leave-one-family-out", flush=True)
    full_dga = models.load_model("dga", config.SEED)
    lofo_rows, lofo_chart = _leave_one_family_out(full_dga, config.SEED) if not args.quick else ([], {})
    _figure_bar(config.FIGURES_DIR / "lofo_recall.png", list(lofo_chart),
                list(lofo_chart.values()), "DGA recall on unseen families", "Recall")

    print("external ExtraHop test", flush=True)
    external = _external_test(
        full_dga, 2_000 if args.quick else config.EXTRAHOP_SAMPLE_SIZE,
        config.SEED, load_words(),
        max_source_rows=100_000 if args.quick else None,
    )

    print("evasion tests", flush=True)
    url_rows, dga_evasion_rows, evasion_chart = _evasion(
        models.load_model("phish_host", config.SEED), full_dga, config.SEED
    )
    _figure_bar(config.FIGURES_DIR / "evasion_detection_rate.png",
                list(evasion_chart), list(evasion_chart.values()),
                "Phishing detection after rewriting (seed 42)", "Detection rate")
    print("simulated DNS scanner", flush=True)
    scanner = _scanner_evaluation(config.SEED)

    prevalence_chart = [row for row in prevalence_rows if row["model"] == "phish_host"
                        and row["threshold"] == "1pct"]
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot([row["prevalence"] for row in prevalence_chart],
            [float(row["precision"]) for row in prevalence_chart], marker="o")
    ax.set(title="Precision by prevalence (phish_host, 1%)", ylabel="Precision",
           xlabel="Attack prevalence")
    ax.set_ylim(0, 1)
    fig.tight_layout()
    fig.savefig(config.FIGURES_DIR / "precision_by_prevalence.png", dpi=130)
    plt.close(fig)

    # ---- Assemble the report -----------------------------------------
    lines = [
        "# DomainGuard results",
        "",
        f"Generated {datetime.now(timezone.utc).isoformat()} by `scripts/evaluate.py`.",
        "",
        "## Run metadata",
        "",
        md_table(["Item", "Value"], [
            ["Git commit", _git_hash()],
            ["Data manifest SHA-256", models._manifest_hash()],
            ["Tranco list ID", build_meta.get("tranco_list_id")],
            ["Manifest download dates", ", ".join(
                f"{k}: {v['downloaded_utc'][:10]}" for k, v in sorted(manifest.items())
                if k in {"tranco", "phishing_db_links", "phishing_db_domains", "openphish", "extrahop"}
            )],
            ["Python", platform.python_version()],
            ["scikit-learn", sklearn.__version__],
            ["pandas", pd.__version__],
            ["numpy", np.__version__],
            ["Seeds", ", ".join(map(str, seeds))],
            ["Runtime (seconds)", f"{time.time() - started:.1f}"],
            ["Dataset sizes", json.dumps(build_meta.get("actual_sizes", {}))],
            ["Phishing overlap removed", build_meta.get("phishing_benign_overlap_removed")],
            ["DGA collisions discarded", build_meta.get("dga_collisions_discarded")],
        ]),
        "",
        "## Data notes", "",
        "The historical `ALL-phishing-links.lst` was unavailable (HTTP 503 on the "
        "official mirror and absent from the GitHub repository); the ACTIVE "
        "Phishing.Database files were used instead. "
        f"Unique phishing rows before cleaning: {build_meta.get('phishing_rows_before_cleaning')}; "
        f"duplicates removed: {build_meta.get('phishing_duplicates_removed')}; "
        f"benign overlap removed: {build_meta.get('phishing_benign_overlap_removed')}; "
        f"free-host rows in the split: {build_meta.get('phishing_free_host_rows')}.",
        "",
        "## 11.1 Main metrics (test split)",
        "",
        "Values are mean ± standard deviation over the configured seeds. "
        "Thresholds were set on benign validation scores only. "
        "Proposal targets: phishing F1 above 0.95 at about 1% FPR; DGA at about 1% FPR.",
        "",
    ]
    for name, by_threshold in summary.items():
        for key in THRESHOLDS:
            rows = by_threshold[key]
            agg = aggregate(rows)
            lines += [
                f"### {name} — threshold_{key}",
                "",
                md_table(["Precision", "Recall", "F1", "AUC", "FPR", "TP", "FP", "TN", "FN",
                          "Threshold", "Validation FPR"],
                         [[agg[k] for k in METRIC_KEYS] +
                          [f"{np.mean([r['threshold'] for r in rows]):.4f}",
                           f"{np.mean([r['validation_fpr'] for r in rows]):.4f}"]]),
                "",
            ]

    lines += ["## 11.2 Ablations (seed 42, threshold_1pct)", "",
              md_table(["Model", "Dropped group", "F1", "F1 drop", "FPR", "FPR change"],
                       [[r["model"], r["dropped"], f"{r['f1']:.4f}", f"{r['f1_drop']:+.4f}",
                         f"{r['fpr']:.4f}", f"{r['fpr_change']:+.4f}"] for r in ablation_rows]),
              "", "![Ablation F1 drops](figures/ablation_f1_drop.png)", ""]

    lines += ["## 11.3 Prevalence-aware precision", "",
              "Computed from measured test recall and FPR, not measured directly.", "",
              md_table(["Model", "Threshold", "Prevalence", "Precision", "Recall", "FPR"],
                       [[r["model"], r["threshold"], r["prevalence"], r["precision"],
                         r["recall"], r["fpr"]] for r in prevalence_rows]),
              "", "![Precision by prevalence](figures/precision_by_prevalence.png)", ""]

    lines += ["## 11.4 Leave-one-family-out DGA", "",
              "Trained on four families, tested on the held-out family at the full model's "
              "validation threshold. FPR on benign test rows is roughly constant.", "",
              md_table(["Held out", "Train rows", "Held-out test rows", "Recall",
                        "Benign FPR", "Threshold"],
                       [[r["held_out"], r["train_rows"], r["held_out_test_rows"],
                         r["recall"], r["benign_fpr"], r["threshold"]] for r in lofo_rows]),
              "", "![LOFO recall](figures/lofo_recall.png)", ""]

    lines += ["## 11.5 External real-data test (ExtraHop, test only)", "",
              f"Balanced fixed-seed sample: {external['sample_size']} rows "
              f"({external['cap_per_class']} per class). Not used for training or tuning.", "",
              md_table(["Metric", "Value"], [
                  ["DGA recall", f"{external['recall']:.4f}"],
                  ["Benign FPR", f"{external['fpr']:.4f}"],
                  ["Threshold", f"{external['threshold']:.4f}"],
                  ["Source rows read", sum(external["source_rows_read"].values())],
                  ["Source lines read", external["source_lines_read"]],
              ]), "",
              "Flagged external benign names by simple shape:", "",
              md_table(["Shape", "Rows", "Flagged", "Flag rate"],
                       [[shape, counts[0], counts[1], f"{counts[1] / counts[0]:.4f}"]
                        for shape, counts in sorted(external["shape_counts"].items())]),
              ""]

    lines += ["## 11.6 Evasion tests", "",
              "### URL rewrites on phishing test rows", "",
              "Detection rate uses the 1% threshold of `phish_host` (seed 42).", "",
              md_table(["Transform", "Before", "After", "Drop"],
                       [[r["transform"], r["before"], r["after"], r["drop"]]
                        for r in url_rows]), "",
              "### Dictionary-style DGAs", "",
              md_table(["Evasion family", "Recall"],
                       [[r["family"], r["recall"]] for r in dga_evasion_rows]),
              "", "![Evasion detection rate](figures/evasion_detection_rate.png)", ""]

    lines += ["## 11.7 Scanner on simulated DNS traffic", "",
              "Measured on a labelled simulated log generated from the test partition "
              "(`simulate_dns.py`, fixed seed). Scanner uses the strict 0.1% thresholds; "
              "NXDOMAIN is display-only. These are simulated-traffic numbers, not "
              "real-world accuracy.", "",
              md_table(["Metric", "Value"], [
                  ["Clients / infected clients", f"{scanner['clients']} / {scanner['infected_clients']}"],
                  ["Ranked clients (min flags = 3)", scanner["ranked_clients"]],
                  ["Client TP / FP / FN / TN",
                   f"{scanner['client_tp']} / {scanner['client_fp']} / "
                   f"{scanner['client_fn']} / {scanner['client_tn']}"],
                  ["Client precision", f"{scanner['client_precision']:.4f}"],
                  ["Client recall", f"{scanner['client_recall']:.4f}"],
                  ["Flagged / true malicious domains",
                   f"{scanner['flagged_domains']} / {scanner['true_malicious_domains']}"],
                  ["Domain precision", f"{scanner['domain_precision']:.4f}"],
                  ["Domain recall", f"{scanner['domain_recall']:.4f}"],
              ]), ""]

    lines += ["## Figures", "",
              "- [ROC curves](figures/roc.png)",
              "- [Ablation F1 drops](figures/ablation_f1_drop.png)",
              "- [Leave-one-family-out recall](figures/lofo_recall.png)",
              "- [Evasion detection rate](figures/evasion_detection_rate.png)",
              "- [Precision by prevalence](figures/precision_by_prevalence.png)", ""]

    output = config.RESULTS_DIR / "results.md"
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
