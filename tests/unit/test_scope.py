"""Tests for connectivity/scope.py — host canonicalization and CIDR scope checks."""
from __future__ import annotations

import pytest

from harness.connectivity.scope import canonicalize_host, is_ip_in_scope

# ── canonicalize_host: hostnames ────────────────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    ("https://slack.com/api/x", "slack.com"),
    ("https://SLACK.COM/api/x", "slack.com"),          # case-insensitive
    ("https://slack.com./api/x", "slack.com"),          # trailing dot stripped
    ("https://api.slack.com/x", "api.slack.com"),       # subdomain preserved
])
def test_canonicalize_host_hostnames(url, expected):
    assert canonicalize_host(url) == expected


def test_canonicalize_host_suffix_lookalike_is_not_equal():
    """example.test.evil.test must not canonicalize to match example.test —
    canonicalization normalizes, it never truncates to a shorter suffix."""
    assert canonicalize_host("https://example.test.evil.test/") == "example.test.evil.test"
    assert canonicalize_host("https://example.test.evil.test/") != "example.test"


def test_canonicalize_host_idna():
    assert canonicalize_host("https://xn--e1aybc.test/") == "xn--e1aybc.test"


# ── canonicalize_host: rejections ───────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "not a url",
    "https://",
    "slack.com/api/x",       # no scheme
    "https:///api/x",        # no host
])
def test_canonicalize_host_missing_scheme_or_host(url):
    assert canonicalize_host(url) is None


def test_canonicalize_host_rejects_userinfo_smuggling():
    """https://good.test@evil.test/ must be judged as evil.test, not good.test —
    and this function refuses to pick a side, so it denies outright."""
    assert canonicalize_host("https://good.test@evil.test/") is None


def test_canonicalize_host_never_raises_on_malformed_input():
    malformed = [
        "http://" + "x" * 300 + "/",
        "http://[::ffff:999.999.999.999]/",
        "http://\x00host/",
        "ht!tp://host/",
        "",
    ]
    for url in malformed:
        canonicalize_host(url)  # must not raise


# ── canonicalize_host: loose IPv4 forms ─────────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    ("http://10.10/x", "10.0.0.10"),                # short dotted-quad
    ("http://0177.0.0.1/x", "127.0.0.1"),           # octal
    ("http://2130706433/x", "127.0.0.1"),           # decimal
    ("http://127.0.0.1/x", "127.0.0.1"),            # already canonical
])
def test_canonicalize_host_loose_ipv4_forms(url, expected):
    assert canonicalize_host(url) == expected


def test_canonicalize_host_ipv6_literal():
    assert canonicalize_host("http://[::1]/x") == "::1"


# ── is_ip_in_scope ───────────────────────────────────────────────────────────

def test_is_ip_in_scope_matches_cidr():
    assert is_ip_in_scope("8.8.8.8", ["8.8.8.0/24"]) is True


def test_is_ip_in_scope_no_matching_cidr():
    assert is_ip_in_scope("8.8.8.8", ["1.1.1.0/24"]) is False


def test_is_ip_in_scope_empty_allowlist_denies():
    assert is_ip_in_scope("8.8.8.8", []) is False


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.10", "169.254.0.1"])
def test_is_ip_in_scope_denies_private_by_default_even_if_covered(host):
    """A broad grant like 0.0.0.0/0 must not hand out loopback/private/
    link-local addresses for free — that is exactly the SSRF posture."""
    assert is_ip_in_scope(host, ["0.0.0.0/0"]) is False


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.10", "169.254.0.1"])
def test_is_ip_in_scope_allows_private_when_explicitly_opted_in(host):
    assert is_ip_in_scope(host, ["0.0.0.0/0"], allow_private=True) is True


def test_is_ip_in_scope_non_ip_host_denies():
    assert is_ip_in_scope("slack.com", ["0.0.0.0/0"]) is False


def test_is_ip_in_scope_malformed_cidr_never_raises_and_is_skipped():
    assert is_ip_in_scope("8.8.8.8", ["not-a-cidr", "8.8.8.0/24"]) is True


def test_is_ip_in_scope_ipv6():
    assert is_ip_in_scope("2606:4700:4700::1111", ["2606:4700:4700::/48"]) is True


@pytest.mark.parametrize("host", ["224.0.0.1", "0.0.0.0"])
def test_is_ip_in_scope_denies_multicast_and_unspecified_by_default(host):
    """A broad grant must not hand out multicast or unspecified addresses
    for free either — same SSRF posture as the private/loopback/link-local
    denial, just for the other non-globally-routable ranges."""
    assert is_ip_in_scope(host, ["0.0.0.0/0"]) is False


def test_is_ip_in_scope_allows_multicast_when_explicitly_opted_in():
    assert is_ip_in_scope("224.0.0.1", ["0.0.0.0/0"], allow_private=True) is True


def test_is_ip_in_scope_caches_parsed_cidrs_across_calls():
    """The same allowed_cidrs list is checked on every call in the real
    call sites (a static connector allowlist) — parsing must not repeat."""
    from harness.connectivity.scope import _parse_network

    _parse_network.cache_clear()
    is_ip_in_scope("8.8.8.8", ["8.8.8.0/24"])
    is_ip_in_scope("8.8.8.9", ["8.8.8.0/24"])
    assert _parse_network.cache_info().hits >= 1
