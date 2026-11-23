"""Download public data sources and record a verifiable manifest.

Downloads are idempotent, fail loudly, and never fall back to a different
source. All downloaded bytes stay in the gitignored data/ directory.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from .. import config

CHUNK = 1024 * 1024
LFS_BATCH_URL = (
    "https://github.com/ExtraHop/DGA-Detection-Training-Dataset.git/info/lfs/objects/batch"
)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_and_rows(path: Path, compressed: bool = False) -> tuple[str, int]:
    digest = hashlib.sha256()
    rows = 0
    opener = gzip.open if compressed else open
    with opener(path, "rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
            rows += chunk.count(b"\n")
    return digest.hexdigest(), rows


def _file_size(path: Path) -> int:
    return path.stat().st_size


def _stream(url: str, destination: Path, headers: dict[str, str] | None = None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = Request(url, headers=headers or {"User-Agent": "DomainGuard/0.1"})
    with urlopen(request, timeout=120) as response, destination.open("wb") as out:
        while chunk := response.read(CHUNK):
            out.write(chunk)


def _github_commit_date(repo: str, path: str) -> str | None:
    """Best-effort last commit date for a file, via the public GitHub API."""
    url = f"https://api.github.com/repos/{repo}/commits?path={path}&per_page=1"
    try:
        with urlopen(Request(url, headers={"User-Agent": "DomainGuard/0.1"}), timeout=60) as response:
            payload = json.load(response)
        if payload:
            return payload[0]["commit"]["committer"]["date"]
    except Exception as exc:  # network detail is recorded in the audit doc
        print(f"  warning: could not get commit date for {path}: {exc}", file=sys.stderr)
    return None


def _record(manifest: dict, name: str, source: str, url: str, path: Path,
            rows: int, compressed: bool = False, **extra) -> None:
    sha, counted = _sha256_and_rows(path, compressed=compressed)
    manifest[name] = {
        "source": source,
        "url": url,
        "downloaded_utc": _utc(),
        "file": str(path.relative_to(config.ROOT)).replace("\\", "/"),
        "size_bytes": _file_size(path),
        "sha256": sha,
        "row_count": rows if rows else counted,
        **extra,
    }
    print(f"  {name}: {_file_size(path)} bytes, {rows or counted} rows, sha256={sha[:12]}...")


def _load_manifest() -> dict:
    if config.MANIFEST_PATH.exists():
        with config.MANIFEST_PATH.open(encoding="utf-8") as handle:
            return json.load(handle)
    return {}


def _save_manifest(manifest: dict) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with config.MANIFEST_PATH.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)


def _should_download(path: Path, force: bool) -> bool:
    if path.exists() and path.stat().st_size > 0 and not force:
        print(f"  skip {path.name} (exists; use --force to redownload)")
        return False
    return True


def download_tranco(force: bool = False, prefix: int = 1_000_000) -> None:
    """Resolve the latest list ID through the API, then download its CSV."""
    manifest = _load_manifest()
    with urlopen(Request(config.TRANCO_META_URL, headers={"User-Agent": "DomainGuard/0.1"}), timeout=60) as response:
        meta = json.load(response)
    list_id = meta["list_id"]
    # The API's download field already names the full (1M) prefix.
    download_url = (meta["download"] if prefix == 1_000_000
                    else meta["download"].rsplit("/", 1)[0] + f"/{prefix}")
    destination = config.RAW_DIR / "tranco.csv"
    if _should_download(destination, force):
        print(f"  Tranco list {list_id}: {download_url}")
        _stream(download_url, destination)
    _record(
        manifest, "tranco", "Tranco", download_url, destination,
        0, list_id=list_id, created_on=meta.get("created_on"),
        metadata_url=config.TRANCO_META_URL,
        configuration=meta.get("configuration"),
    )
    _save_manifest(manifest)


def download_phishing_db(force: bool = False) -> None:
    manifest = _load_manifest()
    for name, url in (
        ("phishing_db_links", config.PHISHING_DB_LINKS_URL),
        ("phishing_db_domains", config.PHISHING_DB_DOMAINS_URL),
    ):
        destination = config.RAW_DIR / Path(url).name
        if _should_download(destination, force):
            print(f"  {name}: {url}")
            _stream(url, destination)
        _record(
            manifest, name, "Phishing.Database", url, destination, 0,
            repo="Phishing-Database/Phishing.Database",
            last_commit_utc=_github_commit_date(
                "Phishing-Database/Phishing.Database", Path(url).name
            ),
        )
    _save_manifest(manifest)


def download_openphish(force: bool = False) -> None:
    """Terms checked first; see docs/data_audit.md."""
    manifest = _load_manifest()
    destination = config.RAW_DIR / "openphish-feed.txt"
    if _should_download(destination, force):
        print(f"  openphish: {config.OPENPHISH_FEED_URL}")
        _stream(config.OPENPHISH_FEED_URL, destination)
    _record(
        manifest, "openphish", "OpenPhish community feed",
        config.OPENPHISH_FEED_URL, destination, 0,
        terms_url=config.OPENPHISH_TERMS_URL,
        redistribution="prohibited; raw file stays in gitignored data/raw/",
    )
    _save_manifest(manifest)


def download_extrahop(force: bool = False) -> None:
    """Resolve the Git LFS pointer through GitHub's batch API, then download."""
    manifest = _load_manifest()
    destination = config.RAW_DIR / "extrahop.json.gz"
    if _should_download(destination, force):
        pointer_url = (
            "https://raw.githubusercontent.com/ExtraHop/DGA-Detection-Training-Dataset/"
            "main/dga-training-data-encoded.json.gz"
        )
        with urlopen(Request(pointer_url, headers={"User-Agent": "DomainGuard/0.1"}), timeout=60) as response:
            pointer = response.read().decode("utf-8")
        oid = next(line.split()[-1] for line in pointer.splitlines() if line.startswith("oid "))
        oid = oid.removeprefix("sha256:")
        size = int(next(line.split()[-1] for line in pointer.splitlines() if line.startswith("size ")))
        import requests

        batch = requests.post(
            LFS_BATCH_URL,
            json={"operation": "download", "transfers": ["basic"],
                  "objects": [{"oid": oid, "size": size}]},
            headers={"Accept": "application/vnd.git-lfs+json",
                     "Content-Type": "application/vnd.git-lfs+json"},
            timeout=60,
        ).json()
        if "actions" not in batch["objects"][0]:
            raise RuntimeError(f"Git LFS batch API returned no download action: {batch}")
        href = batch["objects"][0]["actions"]["download"]["href"]
        print(f"  ExtraHop LFS object {oid[:12]}... ({size} bytes)")
        _stream(href, destination, headers={"User-Agent": "DomainGuard/0.1"})
    _record(
        manifest, "extrahop", "ExtraHop DGA dataset", config.EXTRAHOP_REPO_URL,
        destination, 0, compressed=True, license="MIT",
        usage="external test only; never used for training",
        pointer_filename="dga-training-data-encoded.json.gz",
    )
    _save_manifest(manifest)


def download_wordlist(force: bool = False) -> None:
    """Unlicensed ('The Unlicense') word list, committed to the repository."""
    destination = config.ROOT / "domainguard" / "dga" / "wordlist.txt"
    if _should_download(destination, force):
        print(f"  wordlist: {config.WORDLIST_URL}")
        _stream(config.WORDLIST_URL, destination)
    print(f"  wordlist: {_file_size(destination)} bytes")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tranco", action="store_true")
    parser.add_argument("--phishing-db", action="store_true")
    parser.add_argument("--openphish", action="store_true")
    parser.add_argument("--extrahop", action="store_true")
    parser.add_argument("--wordlist", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--prefix", type=int, default=1_000_000,
                        help="Tranco prefix to download (default 1000000)")
    args = parser.parse_args(argv)
    if not any([args.tranco, args.phishing_db, args.openphish, args.extrahop,
                args.wordlist, args.all]):
        parser.error("choose at least one source")

    try:
        if args.all or args.tranco:
            download_tranco(args.force, args.prefix)
        if args.all or args.phishing_db:
            download_phishing_db(args.force)
        if args.all or args.openphish:
            download_openphish(args.force)
        if args.all or args.extrahop:
            download_extrahop(args.force)
        if args.all or args.wordlist:
            download_wordlist(args.force)
    except Exception as exc:
        print(f"DOWNLOAD FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
