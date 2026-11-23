"""One canonical parser for every string DomainGuard scores.

No function in this module makes a network request. tldextract is configured
with a bundled suffix snapshot and an empty URL list so it stays offline.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

import tldextract

# No runtime suffix fetch and no on-disk cache: uses the bundled snapshot.
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_PUNYCODE_LABEL = re.compile(r"(?:^|\.)xn--", re.IGNORECASE)
_PORT = re.compile(r":(\d+)$")


@dataclass(frozen=True)
class Normalized:
    raw: str
    host: str = ""                 # lowercase ASCII host
    host_unicode: str = ""         # punycode-decoded host, if different
    registered_domain: str = ""    # e.g. example.co.uk
    sld_label: str = ""            # e.g. example
    subdomain: str = ""            # leading www. removed for features
    tld: str = ""                  # public suffix, e.g. co.uk
    path: str = ""
    query: str = ""
    is_ip_host: bool = False
    has_userinfo: bool = False
    has_punycode: bool = False
    has_port: bool = False


def _decode_punycode(host: str) -> str:
    """Best-effort IDNA decoding; never raises."""
    parts = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                parts.append(label.encode("ascii").decode("idna"))
                continue
            except (UnicodeError, LookupError):
                pass
        parts.append(label)
    return ".".join(parts)


def _is_ip(host: str) -> bool:
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def normalize(raw: str) -> Normalized:
    """Parse a URL or bare domain into the shared Normalized record.

    Malformed input never raises: callers receive mostly-empty fields and can
    skip the row.
    """
    if raw is None:
        return Normalized(raw="")
    text = str(raw).strip()
    if not text:
        return Normalized(raw="")

    candidate = text if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", text) else "http://" + text
    try:
        split = urlsplit(candidate)
        netloc = split.netloc
        has_userinfo = "@" in netloc
        has_port = bool(_PORT.search(netloc.rsplit("@", 1)[-1]))
        host = (split.hostname or "").strip().rstrip(".").lower()
        # urlsplit keeps IPv6 brackets in netloc but not in hostname.
        if ":" in netloc.rsplit("@", 1)[-1] and not has_port and host.count(":") > 0:
            host = host
        path = split.path or ""
        query = split.query or ""
    except (ValueError, UnicodeError):
        return Normalized(raw=text)

    has_punycode = bool(_PUNYCODE_LABEL.search(host))
    host_unicode = _decode_punycode(host) if has_punycode else host
    is_ip = _is_ip(host)

    registered_domain = sld_label = subdomain = tld = ""
    if host and not is_ip:
        try:
            ext = EXTRACTOR(host)
            sld_label = ext.domain or ""
            tld = ext.suffix or ""
            if sld_label and tld:
                registered_domain = f"{sld_label}.{tld}"
                subdomain = ext.subdomain or ""
            else:
                # Unknown or private suffix: use the whole host as the group key.
                registered_domain = host
                sld_label = sld_label or host.split(".")[0]
        except Exception:  # defensive: tldextract must never break scoring
            registered_domain = host
            sld_label = host.split(".")[0]

    if subdomain.lower().startswith("www."):
        subdomain = subdomain[4:]
    elif subdomain.lower() == "www":
        subdomain = ""

    return Normalized(
        raw=text,
        host=host,
        host_unicode=host_unicode,
        registered_domain=registered_domain,
        sld_label=sld_label,
        subdomain=subdomain,
        tld=tld,
        path=path,
        query=query,
        is_ip_host=is_ip,
        has_userinfo=has_userinfo,
        has_punycode=has_punycode,
        has_port=has_port,
    )


def defang(raw: str) -> str:
    """Display-only defanging; never used for scoring."""
    text = str(raw).strip()
    text = re.sub(r"(?i)^http", "hxxp", text)
    return text.replace(".", "[.]")


def for_dga(name: str) -> str:
    """DGA model input: second-level label only, never a TLD."""
    norm = normalize(name)
    return norm.sld_label
