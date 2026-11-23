"""End-to-end pipeline: download, build, train, evaluate, report."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


def _run(module: str, *args: str) -> None:
    command = [PYTHON, "-m", module, *args]
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--skip-download", action="store_true")
    parser.add_argument("--n-per-class", type=int, default=None)
    args = parser.parse_args(argv)

    started = time.time()
    if not args.skip_download:
        _run("domainguard.data.download", "--all")
    build_args = []
    if args.smoke:
        build_args.append("--smoke")
    if args.n_per_class:
        build_args += ["--n-per-class", str(args.n_per_class)]
    _run("domainguard.data.build", *build_args)
    _run("scripts.train", *(["--quick"] if args.smoke else []))
    _run("scripts.evaluate", *(["--quick"] if args.smoke else []))
    _run("scripts.make_report")
    print(f"run_all completed in {time.time() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
