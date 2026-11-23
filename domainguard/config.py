"""Global settings, paths and small curated word lists.

Everything that is a fixed project decision lives here so it is easy to audit.
"""

from __future__ import annotations

from pathlib import Path

# Reproducibility
SEED = 42
SEEDS = tuple(range(42, 47))
N_PER_CLASS = 150_000
TEST_SIZE = 0.15
VAL_SIZE = 0.15

# Paths (relative to the repository root)
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR = DATA_DIR / "models"
SIM_DIR = DATA_DIR / "sim"
MANIFEST_PATH = DATA_DIR / "manifest.json"
RESULTS_DIR = ROOT / "docs"
FIGURES_DIR = RESULTS_DIR / "figures"
SAMPLES_DIR = ROOT / "samples"
SAMPLE_LOG = SAMPLES_DIR / "sample_dns.log"

MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB, also used by the scanner web form

# Random-forest hyperparameters (fixed by the handout)
RF_PARAMS = {
    "n_estimators": 300,
    "max_depth": None,
    "min_samples_leaf": 5,
    "max_features": "sqrt",
    "class_weight": "balanced",
    "n_jobs": -1,
}

# Keyword tokens. Deliberately small and imperfect; see docs/decisions.md.
KEYWORDS = (
    "login", "secure", "account", "verify", "update", "bank", "signin", "pay",
)
KEYWORD_TO_FEATURE = {
    "login": "kw_login",
    "secure": "kw_secure",
    "account": "kw_account",
    "verify": "kw_verify",
    "update": "kw_update",
    "bank": "kw_bank",
    "signin": "kw_signin",
    "pay": "kw_pay",
}

# Free-hosting / site-builder platforms. Kept, but reported separately because
# phishing pages on these hosts can have a legitimate-looking registered domain.
# Source: providers' own product pages (blogspot.google.com, wix.com,
# weebly.com, wordpress.com, github.com/features/pages, netlify.com,
# vercel.com, squarespace.com, webflow.com, 000webhost.com). Recorded in
# docs/data_audit.md; this list is documented, not authoritative.
FREE_HOSTING_DOMAINS = frozenset({
    "blogspot.com", "googleusercontent.com", "sites.google.com",
    "wixsite.com", "weebly.com", "wordpress.com", "github.io",
    "netlify.app", "vercel.app", "squarespace.com", "webflow.io",
    "000webhostapp.com", "weeblysite.com", "tumblr.com",
})

# Source URLs (verified in docs/data_audit.md)
TRANCO_META_URL = "https://tranco-list.eu/api/lists/date/latest"
PHISHING_DB_LINKS_URL = (
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
    "master/phishing-links-ACTIVE.txt"
)
PHISHING_DB_ALL_LINKS_URL = (
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
    "master/ALL-phishing-links.lst"
)
PHISHING_DB_DOMAINS_URL = (
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
    "master/phishing-domains-ACTIVE.txt"
)
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
OPENPHISH_TERMS_URL = "https://www.openphish.com/terms.html"
EXTRAHOP_URL = (
    "https://media.githubusercontent.com/media/ExtraHop/"
    "DGA-Detection-Training-Dataset/main/dga-training-data-encoded-v3.json.gz"
)
EXTRAHOP_REPO_URL = "https://github.com/ExtraHop/DGA-Detection-Training-Dataset"
WORDLIST_URL = (
    "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"
)
WORDLIST_LICENSE_URL = "https://github.com/dwyl/english-words/blob/master/LICENSE.md"

# External test sample size (fixed by the handout)
EXTRAHOP_SAMPLE_SIZE = 200_000
