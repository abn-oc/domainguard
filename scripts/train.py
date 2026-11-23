"""Train the three detectors with the configured seeds."""

from __future__ import annotations

import argparse
import time

from domainguard import config
from domainguard.models import MODEL_TYPES, train_model


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", nargs="+", choices=MODEL_TYPES,
                        default=list(MODEL_TYPES))
    parser.add_argument("--seeds", nargs="+", type=int, default=list(config.SEEDS))
    parser.add_argument("--quick", action="store_true",
                        help="train only seed 42 (for smoke tests)")
    args = parser.parse_args(argv)
    seeds = [config.SEED] if args.quick else args.seeds

    started = time.time()
    for name in args.models:
        for seed in seeds:
            print(f"[{name}] seed {seed}", flush=True)
            train_model(name, seed)
    print(f"training completed in {time.time() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
