# DomainGuard

DomainGuard is a CS3002 Information Security term-project prototype that detects
phishing URLs and algorithmically generated (DGA) domains from **text only**.
It never makes a network request to a URL or domain it scores: no DNS lookup, no
HTTP fetch, no WHOIS.

This is a student prototype, not a production security product. It is licensed
under no formal licence (the repository deliberately has no LICENSE file).

## What is in here

- Three random-forest detectors: `phish_host` (primary, host features),
  `phish_full` (host + path/query comparison), and `dga` (second-level label).
- A reproducible data pipeline with pinned Tranco list, hashed downloads and
  grouped 70/15/15 splits by registered domain.
- An evaluation suite covering ablations, prevalence, leave-one-family-out DGA,
  an external real-data test, string-only evasion, and a simulated DNS scanner.
- A streaming DNS-log scanner, a labelled-log simulator, a CLI and a two-page
  Flask demo.

## Install

The project was built and tested on Python 3.14.7 (Python 3.11 was not available
in the build environment; see `docs/decisions.md`).

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pip install -e .
```

## Five-minute demo

The committed sample log needs no downloaded data. Trained models are required
for `check` and `scan`; they are produced by the training command below and are
never committed.

```bash
# Check one URL (exit code 1 means flagged, 0 means benign, 2 means input error)
.venv\Scripts\python.exe -m domainguard.cli check https://paypa1-secure.com/login --json

# Scan the committed sample DNS log
.venv\Scripts\python.exe -m domainguard.cli scan samples/sample_dns.log --out data/sim

# Start the local web demo, then open http://127.0.0.1:5000/
.venv\Scripts\python.exe -m domainguard.web.app
```

The web app binds to `127.0.0.1`, has debug off, autoescapes all input, requires
a per-session CSRF token, caps uploads at 20 MB and deletes temporary files
before responding. Input is displayed defanged (`hxxp`, `[.]`).

## Reproduce the results

```bash
# 1. Download and verify the public sources (writes data/manifest.json)
.venv\Scripts\python.exe -m domainguard.data.download --all

# 2. Clean, dedupe and split
.venv\Scripts\python.exe -m domainguard.data.build

# 3. Train five seeds (about one hour at the default 150,000 per class)
.venv\Scripts\python.exe -m scripts.train

# 4. Evaluate and regenerate docs/results.md plus figures
.venv\Scripts\python.exe -m scripts.evaluate

# 5. Verify the report exists and has all sections
.venv\Scripts\python.exe -m scripts.make_report

# All-in-one, with downloads skipped and a tiny smoke fixture
.venv\Scripts\python.exe -m scripts.run_all --smoke --skip-download

# Unit, no-network, leakage, determinism and web tests
.venv\Scripts\python.exe -m pytest -q
```

Data, models, raw logs and `results_raw/` are gitignored. OpenPhish's feed is
never committed or redistributed. The word list is committed because its
license (The Unlicense) permits redistribution.

## Measured results summary

Full detail, including every seed, threshold and ablation, is in
`docs/results.md`. Figures are in `docs/figures/`.

| Target | Measured result | Met? |
|---|---|---|
| Phishing F1 above 0.95 at about 1% FPR | `phish_host` F1 0.8101 ± 0.0003, FPR 0.0105 ± 0.0002 (5 seeds) | Missed |
| DGA on unseen families at about 1% FPR | Leave-one-family-out mean recall 0.3163 (0.0011–0.9663 across 5 families), benign FPR 0.0072–0.0127; in-domain F1 0.8877 ± 0.0012 at FPR 0.0104 | Missed |
| Evasion tests reported | 6 URL rewrites and 4 dictionary-style DGA families in `docs/results.md` §11.6 | Met |
| CLI / scanner / web demo offline | 47 tests pass, including a network-blocked check/scan test and CSRF/web checks | Met |

The dataset snapshot is dated 2026-11-23 (Tranco list `8PW6V`). Same method,
data snapshot dated 2026-11-23: changing the feeds changes the numbers.

## Documentation

- `docs/architecture.md` — components and data flow.
- `docs/data_audit.md` — sources, hashes, row counts, terms and blockers.
- `docs/decisions.md` — assumptions and deviations from the handout.
- `docs/results.md` — generated results, never hand-edited.
- `docs/security_analysis.md` — what works, what does not, and why.

## Attribution

Benign domains: [Tranco](https://tranco-list.eu/) list `8PW6V`.
Phishing data: [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database)
and the [OpenPhish community feed](https://openphish.com/) (academic use; not
redistributed). External DGA test data:
[ExtraHop DGA Detection Training Dataset](https://github.com/ExtraHop/DGA-Detection-Training-Dataset)
(test only). Word list: [dwyl/english-words](https://github.com/dwyl/english-words)
(The Unlicense).

## Disclaimer

This is a class project. It is not a production security control, and its flags
must not be used to block traffic or accuse a user without human review.
