"""Five DGA families defined only by output shape.

These generators create plain lowercase domain-label strings for training
data. They contain no malware logic, no network behavior and no family names
taken from real malware.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

from ..config import SEED

WORDLIST_PATH = Path(__file__).with_name("wordlist.txt")
CONSONANTS = "bcdfghjklmnpqrstvwxyz"
VOWELS = "aeiou"
HEX_CHARS = "0123456789abcdef"
ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"

# Guard against accidental brand/TLD/proper-noun output from the word list.
_BLOCKED_WORDS = frozenset({
    "paypal", "ebay", "amazon", "microsoft", "google", "apple", "facebook",
    "instagram", "whatsapp", "netflix", "chase", "steam", "coinbase",
    "binance", "dropbox", "adobe", "linkedin", "twitter", "yahoo", "bank",
    "com", "net", "org", "info", "biz", "online", "site", "club", "shop",
})

FAMILIES = (
    "rand_alnum", "hex", "cv_pronounceable", "sparse_digits", "dict_join",
)


def load_words() -> tuple[str, ...]:
    if not WORDLIST_PATH.exists():
        raise FileNotFoundError(
            f"{WORDLIST_PATH} missing; run `python -m domainguard.data.download --wordlist`"
        )
    brands_path = Path(__file__).resolve().parent.parent / "brands.json"
    brands = json.loads(brands_path.read_text(encoding="utf-8"))
    brand_tokens = tuple(brands)
    words = []
    for line in WORDLIST_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        word = line.strip().lower()
        if (3 <= len(word) <= 9 and word.isalpha() and word not in _BLOCKED_WORDS
                and not any(token in word for token in brand_tokens)):
            words.append(word)
    if len(words) < 1000:
        raise ValueError("word list unexpectedly small after filtering")
    return tuple(words)


def _family_rng(family: str, seed: int) -> random.Random:
    return random.Random(seed + FAMILIES.index(family))


def _rand_alnum(rng: random.Random) -> str:
    return "".join(rng.choice(ALNUM) for _ in range(rng.randint(8, 20)))


def _hex(rng: random.Random) -> str:
    return "".join(rng.choice(HEX_CHARS) for _ in range(rng.randint(16, 32)))


def _cv_pronounceable(rng: random.Random) -> str:
    length = rng.randint(8, 16)
    # Alternate consonant/vowel; occasionally swap the starting class.
    start_consonant = rng.random() < 0.8
    out = []
    for i in range(length):
        consonant = start_consonant if i % 2 == 0 else not start_consonant
        out.append(rng.choice(CONSONANTS if consonant else VOWELS))
    return "".join(out)


def _sparse_digits(rng: random.Random) -> str:
    length = rng.randint(10, 18)
    chars = [rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(length)]
    for position in rng.sample(range(length), rng.randint(1, 3)):
        chars[position] = rng.choice("0123456789")
    return "".join(chars)


def _dict_join(rng: random.Random, words: tuple[str, ...]) -> str:
    for _ in range(50):
        count = rng.choice((2, 2, 3))
        joined = "".join(rng.choice(words) for _ in range(count))
        if 8 <= len(joined) <= 24:
            return joined
    return "".join(rng.choice(words) for _ in range(2))[:24]


def generate_family(family: str, n: int, seed: int = SEED,
                    excluded: set[str] | None = None,
                    words: tuple[str, ...] | None = None) -> tuple[list[str], int]:
    """Generate n unique labels for one family; returns (names, collisions)."""
    if family not in FAMILIES:
        raise ValueError(f"unknown family: {family}")
    rng = _family_rng(family, seed)
    excluded = excluded or set()
    words = words if words is not None else load_words()
    makers = {
        "rand_alnum": lambda: _rand_alnum(rng),
        "hex": lambda: _hex(rng),
        "cv_pronounceable": lambda: _cv_pronounceable(rng),
        "sparse_digits": lambda: _sparse_digits(rng),
        "dict_join": lambda: _dict_join(rng, words),
    }
    result: list[str] = []
    seen: set[str] = set()
    collisions = 0
    while len(result) < n:
        name = makers[family]()
        if name in excluded or name in seen:
            collisions += 1
            continue
        seen.add(name)
        result.append(name)
    return result, collisions


def generate_all(n_per_class: int, seed: int = SEED,
                 excluded: set[str] | None = None) -> tuple[list[tuple[str, str]], int]:
    """Split n_per_class evenly across the five families."""
    words = load_words()
    excluded = set(excluded or ())
    rows: list[tuple[str, str]] = []
    collisions = 0
    base = n_per_class // len(FAMILIES)
    for index, family in enumerate(FAMILIES):
        count = base + (1 if index < n_per_class % len(FAMILIES) else 0)
        names, skipped = generate_family(family, count, seed, excluded | set(n for n, _ in rows), words)
        rows.extend((name, family) for name in names)
        collisions += skipped
    return rows, collisions
