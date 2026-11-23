"""Streaming readers for Zeek TSV, Zeek JSON lines and simple CSV DNS logs.

Parsers never execute log content and never resolve queried names.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterator

REQUIRED = ("ts", "id.orig_h", "query")


class LogParser:
    """Streaming parser with a malformed-line counter."""

    def __init__(self, path: str | Path, fmt: str = "auto"):
        self.path = Path(path)
        self.malformed = 0
        self.lines = 0
        self.format = fmt if fmt != "auto" else self._detect()

    def _detect(self) -> str:
        with self.path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith("{"):
                    return "json"
                if stripped.startswith("timestamp,client_ip,query"):
                    return "csv"
                return "zeek"
        return "zeek"

    def records(self) -> Iterator[dict]:
        if self.format == "json":
            yield from self._json_records()
        elif self.format == "csv":
            yield from self._csv_records()
        elif self.format == "zeek":
            yield from self._zeek_records()
        else:
            raise ValueError(f"unknown log format: {self.format}")

    def _valid(self, record: dict) -> bool:
        self.lines += 1
        if not all(record.get(field) for field in REQUIRED):
            self.malformed += 1
            return False
        return True

    def _json_records(self) -> Iterator[dict]:
        with self.path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except (ValueError, TypeError):
                    self.lines += 1
                    self.malformed += 1
                    continue
                if isinstance(record, dict) and self._valid(record):
                    yield record

    def _csv_records(self) -> Iterator[dict]:
        with self.path.open(encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                record = {
                    "ts": row.get("timestamp", ""),
                    "id.orig_h": row.get("client_ip", ""),
                    "query": row.get("query", ""),
                    "rcode_name": row.get("rcode_name", ""),
                }
                if self._valid(record):
                    yield record

    def _zeek_records(self) -> Iterator[dict]:
        fields: list[str] | None = None
        defaults = ["ts", "id.orig_h", "query", "rcode_name"]
        with self.path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\r\n")
                if line.startswith("#"):
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                    continue
                if not line.strip():
                    continue
                parts = ["" if value == "-" else value for value in line.split("\t")]
                names = fields or defaults
                record = dict(zip(names, parts))
                if self._valid(record):
                    yield record
