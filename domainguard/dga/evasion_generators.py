"""Evaluation-only dictionary-style DGA recipes.

These are simple string transformations used to probe the trained detector.
They are never used for training and contain no timing, network or infection
logic.
"""

from __future__ import annotations

import random

from ..config import SEED
from .generators import VOWELS, load_words

EVASION_FAMILIES = (
    "dict_join_hyphen", "dict_join_digits", "dict_join_three",
    "rand_alnum_syllable",
)
SYLLABLES = ("tion", "ment", "ness", "able", "ing", "ster", "lock")


def generate_evasion_family(family: str, n: int, seed: int = SEED) -> list[str]:
    rng = random.Random(seed + 1000 + EVASION_FAMILIES.index(family))
    words = load_words()
    out: list[str] = []
    seen: set[str] = set()
    while len(out) < n:
        if family == "dict_join_hyphen":
            name = "-".join(rng.choice(words) for _ in range(2))
        elif family == "dict_join_digits":
            name = "".join(rng.choice(words) for _ in range(2)) + f"{rng.randint(10, 99)}"
        elif family == "dict_join_three":
            name = "".join(rng.choice(words) for _ in range(3))
        elif family == "rand_alnum_syllable":
            prefix = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(5, 10)))
            syllable = rng.choice(SYLLABLES)
            name = prefix + syllable + rng.choice(VOWELS) + rng.choice("abcdefghijklmnopqrstuvwxyz")
        else:
            raise ValueError(f"unknown evasion family: {family}")
        if 6 <= len(name) <= 40 and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def generate_all_evasion(n: int, seed: int = SEED) -> list[tuple[str, str]]:
    return [
        (name, family)
        for family in EVASION_FAMILIES
        for name in generate_evasion_family(family, n, seed)
    ]
