"""Package metadata contract.

`harness.__version__` is read from installed distribution metadata by name, and
a wrong name does not raise — `PackageNotFoundError` is caught and the sentinel
`0.0.0+dev` is returned. So a rename of the distribution silently detaches the
version from reality, and the failure is invisible in a source checkout where
the sentinel is the correct answer anyway.

It surfaced exactly that way: the distribution was renamed to `shai-harness`
while `__init__.py` still looked up `shai`, so every startup attestation on a
correct install recorded `shai_version="0.0.0+dev"` — a signed audit record
whose purpose is attesting which version wired the process.
"""
from __future__ import annotations

import tomllib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest

import harness

_PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _declared_distribution_name() -> str:
    if not _PYPROJECT.exists():
        pytest.skip("pyproject.toml not found (installed package, not a checkout)")
    return tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["name"]


def test_version_matches_installed_distribution():
    """__version__ must be the version of the distribution pyproject declares.

    Reads the name from pyproject rather than hardcoding it, so a future rename
    fails here instead of silently reintroducing the sentinel.
    """
    name = _declared_distribution_name()
    try:
        installed = version(name)
    except PackageNotFoundError:
        pytest.skip(f"{name} not installed — nothing to compare against")

    assert harness.__version__ == installed, (
        f"harness.__version__ is {harness.__version__!r} but distribution "
        f"{name!r} is {installed!r} — __init__.py is looking up a different "
        f"distribution name, and the mismatch is swallowed as '0.0.0+dev'"
    )


def test_version_is_not_the_sentinel_when_installed():
    """The sentinel is correct only for a source tree with nothing installed."""
    name = _declared_distribution_name()
    try:
        version(name)
    except PackageNotFoundError:
        pytest.skip(f"{name} not installed — sentinel is the correct answer")

    assert harness.__version__ != "0.0.0+dev", (
        f"{name} is installed but __version__ fell back to the sentinel, so the "
        f"startup attestation records a version that is not the one running"
    )
