import pytest

from domainguard.normalize import defang, normalize


def test_uppercase_and_no_scheme():
    n = normalize("HTTP://EXAMPLE.COM/Path?X=1")
    assert n.host == "example.com"
    assert n.registered_domain == "example.com"
    assert n.sld_label == "example"
    assert n.path == "/Path"  # path case is preserved


def test_port_and_userinfo():
    n = normalize("user:pass@Example.com:8443/login")
    assert n.has_userinfo is True
    assert n.has_port is True
    assert n.host == "example.com"


def test_trailing_dot():
    n = normalize("example.com.")
    assert n.host == "example.com"
    assert n.registered_domain == "example.com"


def test_idn_punycode():
    n = normalize("xn--bcher-kva.example")
    assert n.host == "xn--bcher-kva.example"
    assert n.has_punycode is True
    assert "bücher" in n.host_unicode


def test_ip_hosts():
    assert normalize("http://192.168.1.1/x").is_ip_host is True
    assert normalize("http://[2001:db8::1]/").is_ip_host is True
    assert normalize("8.8.8.8").is_ip_host is True
    assert normalize("example.com").is_ip_host is False


def test_www_stripped_for_features():
    n = normalize("https://www.news.bbc.co.uk/a")
    assert n.subdomain == "news"
    assert n.registered_domain == "bbc.co.uk"
    assert n.tld == "co.uk"
    assert n.sld_label == "bbc"


def test_multipart_tld():
    n = normalize("shop.example.co.uk")
    assert n.registered_domain == "example.co.uk"
    assert n.tld == "co.uk"


@pytest.mark.parametrize("bad", ["", "   ", "!!!!!", "http://", "http:///nope", None])
def test_bad_input_never_raises(bad):
    n = normalize(bad)
    assert isinstance(n.raw, str)


def test_offline_extractor():
    from domainguard.normalize import EXTRACTOR

    assert EXTRACTOR.suffix_list_urls == ()
    assert EXTRACTOR("example.co.uk").suffix == "co.uk"


def test_defang_display_only():
    assert defang("http://evil.example.com") == "hxxp://evil[.]example[.]com"
