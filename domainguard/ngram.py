"""Character trigram language model with out-of-fold scoring.

Only benign training strings are used to fit it. Scoring is mean log
probability per character with add-one smoothing; a row in the training set
is always scored by a model that did not see that row.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from typing import Iterable, Sequence

PAD = "#"


def _triples(name: str):
    padded = PAD * 2 + str(name) + PAD
    for i in range(2, len(padded) - 1):
        yield padded[i - 2:i], padded[i]


def _log(value: float) -> float:
    return math.log(value) if value > 0 else -30.0


class CharTrigram:
    """Add-one-smoothed character trigram model."""

    def __init__(self, counts: dict[tuple[str, str], int] | None = None):
        self.counts: Counter[tuple[str, str]] = Counter(counts or {})
        self.contexts: Counter[str] = Counter()
        for (context, _char), count in self.counts.items():
            self.contexts[context] += count
        self.vocab = len({char for (_context, char) in self.counts})

    @classmethod
    def fit(cls, names: Iterable[str]) -> "CharTrigram":
        counts: Counter[tuple[str, str]] = Counter()
        for name in names:
            counts.update(_triples(str(name)))
        return cls(dict(counts))

    def to_dict(self) -> dict:
        """Serializable representation stored in the model file."""
        return {
            "counts": [[ctx, char, n] for (ctx, char), n in sorted(self.counts.items())],
            "vocab": self.vocab,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CharTrigram":
        counts = {(ctx, char): n for ctx, char, n in data["counts"]}
        model = cls(counts)
        model.vocab = int(data.get("vocab", model.vocab))
        return model

    def score(self, name: str) -> float:
        """Mean log probability per character (0.0 for an empty string)."""
        triples = list(_triples(str(name)))
        if not triples:
            return 0.0
        total = 0.0
        for context, char in triples:
            numerator = self.counts[(context, char)] + 1
            denominator = self.contexts[context] + self.vocab
            total += _log(numerator / denominator)
        return total / len(triples)

    def score_many(self, names: Sequence[str]) -> list[float]:
        return [self.score(name) for name in names]


def out_of_fold_scores(names: Sequence[str], n_folds: int = 5,
                       seed: int = 42) -> list[float]:
    """Score benign training names without ever scoring a name with itself."""
    names = [str(n) for n in names]
    triples_by_row = [list(_triples(name)) for name in names]
    folds: list[list[int]] = [[] for _ in range(n_folds)]
    order = list(range(len(names)))
    random.Random(seed).shuffle(order)
    for fold_index, row_index in enumerate(order):
        folds[fold_index % n_folds].append(row_index)

    scores = [0.0] * len(names)
    for fold_index, held_out_rows in enumerate(folds):
        counts: Counter[tuple[str, str]] = Counter()
        contexts: Counter[str] = Counter()
        for other_index, rows in enumerate(folds):
            if other_index == fold_index:
                continue
            for row_index in rows:
                counts.update(triples_by_row[row_index])
                contexts.update(ctx for ctx, _ch in triples_by_row[row_index])
        vocab = len({char for (_ctx, char) in counts})
        for row_index in held_out_rows:
            triples = triples_by_row[row_index]
            if not triples:
                continue
            total = 0.0
            for context, char in triples:
                numerator = counts[(context, char)] + 1
                denominator = contexts[context] + vocab
                total += _log(numerator / denominator)
            scores[row_index] = total / len(triples)
    return scores
