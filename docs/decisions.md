# Decisions and deviations from the handout

Fixed decisions from the handout are not re-litigated here. This file records
assumptions and places where the observed world differed from the handout.

1. **Python version.** The handout says Python 3.11. The build environment has
   Python 3.14.7 (and 3.12) but no 3.11 interpreter, so the project was built
   and tested on 3.14. `requirements.txt` is pinned to the versions that
   passed the test suite there. No 3.11-specific behaviour is used.
2. **Tranco download URL.** The API metadata field `download` already includes
   the 1M prefix (`.../download/<id>/1000000`). Appending another `/1000000`
   returns 404. The downloader uses the field directly for the default prefix.
   Pinned list ID: 8PW6V (2026-11-22).
3. **Tranco API instead of the `tranco` package.** The handout allows either.
   Direct HTTP calls to the documented API avoid an extra dependency and make
   the exact URL and list ID available for the manifest.
4. **ExtraHop filename and delivery.** The repository contains
   `dga-training-data-encoded.json.gz` (not `...-v3...`), stored in Git LFS.
   The downloader resolves the LFS pointer via GitHub's batch API. The
   decompressed file has a six-line copyright header followed by plain-text
   JSON lines; `domain` values are plain strings without TLDs. File name in
   the README is inconsistent with the repository — recorded in the audit.
5. **Historical phishing list unavailable.** `ALL-phishing-links.lst` is not in
   the GitHub repository and the official phish.co.za mirror returned HTTP
   503. We did not substitute an unverified mirror. Both ACTIVE files (links
   and domains) are used, plus OpenPhish where its terms allow. The ACTIVE
   links file's last commit is 2025-12-22, so staleness is reported rather
   than hidden.
6. **Phishing deduplication.** Full normalized URL deduplication is followed by
   keeping one row per registered domain, preferring link rows over bare domain
   rows. This is a stronger form of the handout's "within each split" rule and
   guarantees the grouped-split invariant.
7. **Split assignment.** Domain groups are shuffled with the global seed and
   greedily assigned to the split with the most remaining capacity until the
   70/15/15 targets are met. This keeps class sizes near the requested count
   without splitting a registered domain across partitions.
8. **DGA benign side.** DGA benign rows come from the Tranco train partition,
   then are split 70/15/15 by registered domain. DGA test benign names are
   therefore unseen by DGA training, which the simulator's leakage test
   verifies. ExtraHop benign names are never used in training.
9. **Simulation TLD.** DGA labels are TLD-less by design. For DNS log realism,
   simulated DGA queries append the reserved `.example` suffix. This is a log
   formatting choice only; the DGA model still scores only the second-level
   label.
10. **Check threshold.** `domainguard check` and `/check` display verdicts at
    `threshold_1pct` (the proposal's headline operating point). The DNS scanner
    uses the stricter `threshold_0p1pct` by default, as required.
11. **Feature contributions.** `check` ranks the top five features by
    value × global forest importance. It is an approximate, global explanation,
    not a per-prediction causal attribution. SHAP remains a stretch goal.
12. **Ablation and LOFO thresholds.** Ablated models use their own validation
    thresholds, so the reported F1/FPR change reflects a fully retrained
    model. Leave-one-family-out uses the full model's fixed validation
    threshold, as the handout specifies.
13. **Word list.** `dwyl/english-words` is The Unlicense, so the file is
    committed. Words of length 3–9 are used, with brand tokens and common TLDs
    filtered out.
14. **No team ownership.** As directed, no owners are assigned to any task.
15. **Per-split class balance.** The cleaned phishing source produced about
    150,000 unique domains. With a requested 150,000 per class this gives
    105,000 / 22,500 / 22,500 malicious rows per split. Benign rows in the
    phishing frames are sampled down to the same counts, so every split is
    50/50. No malicious rows are invented. The actual counts are in
    `data/processed/build_meta.json` and `docs/results.md`.
16. **Feature-cache optimisation.** Brand fuzzy similarity is cached by
    (`sld`, `registered_domain`) and precomputed normalisation is reused when
    building training matrices. This changes no feature value; it only avoids
    repeating identical work across models. Model artefacts are joblib-compressed
    to keep them out of disk trouble; loading behaviour is unchanged.
17. **Smoke run.** `run_all.py --smoke` reads only the first 50,000 lines of
    each raw source and uses a 2,000-row external sample drawn from the first
    100,000 ExtraHop lines. This is a pipeline check, not a result: the full
    run uses all rows. Measured smoke runtime was 88 seconds.
18. **Simulator volume.** The committed sample log and the scanner evaluation
    use 60 malicious queries per infected client (CLI default remains 8). At the
    scanner's strict 0.1% threshold the phishing model detects bare registered
    domains poorly, so this volume is needed for the minimum-evidence rule to
    produce ranked clients. The resulting recall is reported honestly in
    `docs/results.md`.
