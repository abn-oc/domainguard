import json

import pytest

from domainguard.scanner import dns_scan
from domainguard.scanner.parse import LogParser


def test_zeek_tsv_parser(tmp_path):
    log = tmp_path / "dns.log"
    log.write_text(
        "#separator \\x09\n#fields\tts\tid.orig_h\tquery\trcode_name\n"
        "1.0\t10.0.0.1\texample.com\t-\n"
        "2.0\t10.0.0.2\t-\tNOERROR\n"
        "bad line\n",
        encoding="utf-8",
    )
    parser = LogParser(log, "auto")
    records = list(parser.records())
    assert parser.format == "zeek"
    assert len(records) == 1
    assert records[0]["query"] == "example.com"
    assert parser.malformed == 2


def test_json_and_csv_parsers(tmp_path):
    json_log = tmp_path / "dns.json"
    json_log.write_text(
        '{"ts":1,"id.orig_h":"10.0.0.1","query":"a.com","rcode_name":"NXDOMAIN"}\n'
        "not json\n", encoding="utf-8"
    )
    parser = LogParser(json_log)
    assert parser.format == "json"
    assert len(list(parser.records())) == 1

    csv_log = tmp_path / "dns.csv"
    csv_log.write_text(
        "timestamp,client_ip,query,rcode_name\n1,10.0.0.1,b.com,\n", encoding="utf-8"
    )
    assert len(list(LogParser(csv_log).records())) == 1


def test_ranking_min_evidence_and_nxdomain_display_only(tmp_path, monkeypatch):
    log = tmp_path / "dns.log"
    lines = ["#fields\tts\tid.orig_h\tquery\trcode_name"]
    for i in range(4):
        lines.append(f"{i}\t10.0.0.1\tdga{i}.example\tNXDOMAIN")
    lines.append("5\t10.0.0.2\tone.example\tNXDOMAIN")
    log.write_text("\n".join(lines), encoding="utf-8")

    fake_model = {"thresholds": {"threshold_0p1pct": 0.5}}
    monkeypatch.setattr(dns_scan.models, "load_model", lambda name: fake_model)
    monkeypatch.setattr(
        dns_scan.models, "score",
        lambda model, values: [0.99 if str(v).startswith("dga") else 0.01 for v in values],
    )

    report = dns_scan.scan_log(log, min_flags=3)
    assert [row["client"] for row in report["ranked_clients"]] == ["10.0.0.1"]
    row = report["ranked_clients"][0]
    assert row["flagged_domains"] == 4
    assert row["nxdomain_rate"] == 1.0  # displayed, not used to rank
    assert set(report["flagged_domains"]) == {f"dga{i}.example" for i in range(4)}
    assert report["thresholds"]["threshold_key"] == "threshold_0p1pct"
