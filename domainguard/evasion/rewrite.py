"""URL rewrite transforms for string-only evasion tests.

Every transform edits characters in an already-known URL string. No network
request, DNS lookup or live infrastructure is involved.
"""

from __future__ import annotations

from urllib.parse import quote

from ..normalize import normalize

KINDS = ("percent", "case", "subdomain", "path", "hyphen", "homoglyph")


def rewrite(url: str, kind: str) -> str:
    """Return a rewritten URL for one of the fixed evasion transforms."""
    norm = normalize(url)
    host = norm.host
    sld = norm.sld_label
    if not host:
        return url
    if kind == "percent":
        index = next((i for i, ch in enumerate(host) if ch.isalpha()), 0)
        new_host = host[:index] + quote(host[index], safe="") + host[index + 1:]
    elif kind == "case":
        new_host = host.upper()
    elif kind == "subdomain":
        new_host = "login." + host
    elif kind == "path":
        return url.rstrip("/") + "/index.html"
    elif kind == "hyphen":
        middle = len(sld) // 2
        new_sld = sld[:middle] + "-" + sld[middle:]
        new_host = host.replace(sld, new_sld, 1)
    elif kind == "homoglyph":
        for wrong, right in (("o", "0"), ("l", "1"), ("e", "3"), ("a", "4")):
            if wrong in host:
                new_host = host.replace(wrong, right, 1)
                break
        else:
            new_host = host
    else:
        raise ValueError(kind)
    path = norm.path + ("?" + norm.query if norm.query else "")
    return f"http://{new_host}{path}"
