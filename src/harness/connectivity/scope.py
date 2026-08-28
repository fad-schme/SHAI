"""Host canonicalization and CIDR scope checks for outbound-URL matching.

Two pure functions used wherever SHAI compares an agent- or tool-supplied
URL against an operator-declared allowlist: canonicalize_host() reduces a
URL to the host string the network stack will actually dial, and
is_ip_in_scope() checks a canonical IP address against a CIDR allowlist.

Both exist because a raw string comparison on a URL — case, IDNA variants,
userinfo, and "loose" IPv4 forms (short, octal, decimal) all resolve
differently at the socket layer than they read in the string — lets an
attacker-controlled destination dodge a matcher that never accounts for
them. Neither function raises; a value that fails to parse is out of scope.
"""
from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from urllib.parse import urlsplit


def canonicalize_host(url: str) -> str | None:
    """Reduce a URL to the canonical host string the network stack would dial.

    Returns None (never raises) when:
    - the scheme or host is missing
    - the authority carries userinfo ("user@host") — that syntax puts an
      attacker-controlled host after the "@", where a matcher scanning for
      a prefix could be fooled by what comes before it
    - the host fails to parse as either a hostname or an IP literal

    A bare hostname is lowercased, has its trailing dot stripped, and is
    IDNA-encoded. An IP-literal host is resolved to the same address
    socket.inet_aton would hand the OS, including "loose" IPv4 forms a
    string matcher would otherwise miss: short dotted-quad (10.10),
    octal (0177.0.0.1), and decimal (2130706433).

    Known limitation: IDNA encoding uses Python's stdlib codec (IDNA2003),
    which maps some compatibility characters (e.g. German "ß") differently
    than the UTS46 processing real resolvers use — an allowlist entry
    written in one form will not reliably match a URL using the other for
    such hosts. Closing this fully needs a UTS46-aware IDNA implementation,
    which the stdlib does not provide.
    """
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None

    if not parsed.scheme or not parsed.hostname:
        return None

    if parsed.username is not None or parsed.password is not None:
        return None

    host = parsed.hostname.rstrip(".")
    if not host:
        return None

    ip_literal = _canonicalize_ip_literal(host)
    if ip_literal is not None:
        return ip_literal

    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _canonicalize_ip_literal(host: str) -> str | None:
    """Return the canonical text form if host is any recognizable IP literal.

    Tries strict parsing first (dotted-quad IPv4, standard IPv6), then falls
    back to the "loose" IPv4 forms socket.inet_aton accepts, so this never
    disagrees with what the OS resolver will actually dial. Returns None
    for a value that is not an IP literal at all — i.e. a regular hostname.
    """
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        packed = socket.inet_aton(host)
    except (OSError, ValueError):
        return None
    return socket.inet_ntoa(packed)


@lru_cache(maxsize=256)
def _parse_network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse a CIDR string once and cache it — allowlists are static and
    reused across every call, so callers should not pay repeated parse cost
    for the same entries. Returns None for a CIDR that doesn't parse."""
    try:
        return ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None


def is_ip_in_scope(
    host: str,
    allowed_cidrs: list[str],
    *,
    allow_private: bool = False,
) -> bool:
    """Return True if host is an IP address covered by allowed_cidrs.

    A private, loopback, link-local, multicast, reserved, or unspecified
    address is denied even when a listed CIDR nominally covers it (e.g. a
    broad "0.0.0.0/0" grant), unless allow_private=True — an operator has
    to opt into these non-globally-routable destinations explicitly rather
    than get them for free from a wide allowlist. A host that isn't a
    parseable IP, or a CIDR entry that isn't a parseable network, never
    raises; both simply fail the check.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False

    covered = any(
        (network := _parse_network(cidr)) is not None and address in network
        for cidr in allowed_cidrs
    )
    if not covered:
        return False

    if allow_private:
        return True

    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _is_ip_literal(host: str) -> bool:
    """True if host (already run through canonicalize_host) is an IP address."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def check_scope_policy(
    value: str,
    *,
    allowed_hosts: list[str] | None = None,
    allowed_domains: list[str] | None = None,
    allow_subdomains: bool = False,
    allowed_cidrs: list[str] | None = None,
) -> str | None:
    """Return a violation reason, or None if value's canonical host is in scope.

    value is canonicalized as a URL first (see canonicalize_host) — a
    malformed URL or one carrying userinfo is denied outright, never
    compared against any of the lists below.

    An IP-literal destination can be granted *only* through allowed_cidrs,
    never through allowed_hosts or allowed_domains — otherwise an operator
    typing a literal IP into allowed_hosts (e.g. "127.0.0.1") would bypass
    is_ip_in_scope's private/loopback/link-local/multicast/reserved/
    unspecified default-deny entirely, undermining the deliberate
    extra-opt-in friction that check exists to enforce.

    allowed_hosts    Canonical host must exactly match one of these.
    allowed_domains  Canonical host must equal one of these, or (with
                     allow_subdomains) be a proper subdomain of one.
    allow_subdomains Widen allowed_domains to match subdomains.
    allowed_cidrs    If the canonical host is an IP literal, it must fall
                     inside one of these ranges.
    """
    host = canonicalize_host(value)
    if host is None:
        return "does not resolve to a permitted destination"

    if _is_ip_literal(host):
        if is_ip_in_scope(host, allowed_cidrs or []):
            return None
        return "does not resolve to a permitted destination"

    if allowed_hosts and host in {h.lower() for h in allowed_hosts}:
        return None

    if allowed_domains:
        for domain in (d.lower() for d in allowed_domains):
            if host == domain:
                return None
            if allow_subdomains and host.endswith(f".{domain}"):
                return None

    return "does not resolve to a permitted destination"
