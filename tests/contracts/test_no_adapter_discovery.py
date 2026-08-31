"""SHAI Core ships no adapter discovery, and no way to reach one.

An entry-point group turns *installed* into *imported and executed inside the
process that makes allow/deny decisions* — Python does not otherwise run a
package nobody imports. A hostile or compromised dependency needs no
privileged access to be installed, so a group that SHAI enumerates is a path
from an ordinary supply-chain compromise to arbitrary code in the control
plane, before the scanners, policy engine and emitter it would subvert have
finished being built.

These tests fail the day that capability comes back — by a restored module, a
freshly written one, or a registration in packaging metadata.
"""
from __future__ import annotations

import ast
import tomllib
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _python_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_no_module_enumerates_entry_points():
    """`importlib.metadata.entry_points` is the primitive. Nothing may call it.

    Checked structurally rather than by grep so an aliased import
    (`from importlib import metadata as m; m.entry_points(...)`) is caught too.
    """
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "importlib.metadata":
                names = {a.name for a in node.names}
                if "entry_points" in names:
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
            elif isinstance(node, ast.Attribute) and node.attr == "entry_points":
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert not offenders, (
        "adapter discovery is not part of SHAI Core — entry_points() reached at: "
        + ", ".join(offenders)
    )


def test_no_adapter_discovery_module_exists():
    assert not (SRC / "harness" / "adapters" / "discovery.py").exists()


def test_package_registers_no_adapter_entry_points():
    """Core registers no adapters. A group only exists because something
    registers in it, so an empty declaration is the whole control."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    groups = data.get("project", {}).get("entry-points", {})
    harness_groups = [g for g in groups if g.startswith("harness.")]
    assert not harness_groups, f"unexpected adapter entry-point groups: {harness_groups}"


def test_console_script_is_still_declared():
    """Guard against the deletion above over-reaching: `shai` is a console
    script, not an adapter group, and must survive."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["shai"] == "harness_cli.main:main"
