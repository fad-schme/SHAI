"""Path canonicalization and containment shared by agent grants, the protected
set and the gate.

Containment is decided on the normalized form, never on a raw string prefix:
`/data-evil` is not inside `/data`. `canonicalize_path` is the only function
here that touches the filesystem, and only to resolve symlinks.
"""
from __future__ import annotations

import os
import re
from collections.abc import Sequence
from typing import Any, Literal

_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]+://")

# Which rule denied a path, as recorded on the audit event, and the fixed reason
# text for it. Neither carries the path (Invariant 3).
FsRule = Literal["protected", "outside_read", "outside_write"]
FS_DENY_REASON: dict[str, str] = {
    "protected":     "path is protected",
    "outside_read":  "path not allowed",
    "outside_write": "path not allowed",
}


def is_absolute(path: str) -> bool:
    """True when `path` names a location without reference to a working
    directory: a rooted path, a drive-and-root path, or a UNC path. A
    drive-relative `C:foo` is not absolute."""
    _, rest = os.path.splitdrive(path)
    return rest[:1] in ("/", os.sep)


def _normalized(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def is_within(path: str, root: str) -> bool:
    """True when `path` equals `root` or sits beneath it, comparing normalized
    forms (separators unified, `.` and `..` collapsed, case folded where the
    platform folds it)."""
    p = _normalized(path)
    r = _normalized(root)
    return p == r or p.startswith(r.rstrip(os.sep) + os.sep)


def canonicalize_path(value: Any) -> str | None:
    """The real location `value` names, or None when it cannot be trusted.

    None (never an exception) for a non-string, an empty string, a NUL byte, a
    URI such as `file://...`, a path that is not absolute (SHAI has no working
    directory to resolve it against), or a path the platform cannot resolve.
    Otherwise `..` segments, separators and symlinks are resolved. Resolution
    runs on every call, so a symlink swapped after startup changes the answer.
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    if _URI.match(value) or not is_absolute(value):
        return None
    try:
        return os.path.realpath(value)
    except (OSError, ValueError):
        return None


def check_path(
    value: Any,
    access: Literal["read", "write"],
    *,
    read: Sequence[str],
    write: Sequence[str],
    protected: Sequence[str],
) -> tuple[str | None, FsRule | None]:
    """Decide whether `value` may be used for `access`.

    Returns `(resolved, None)` when it may, and `(None, rule)` when it may
    not, `rule` naming which control refused it. A path in the protected set is
    refused whatever the grant says; otherwise it must sit inside a `write` entry
    (for write access) or a `read` or `write` entry (for read access). Grant
    entries are resolved with the same function as the value, so a symlinked
    root matches what it points to.
    """
    resolved = canonicalize_path(value)
    if resolved is not None and any(is_within(resolved, p) for p in protected):
        return None, "protected"
    entries = write if access == "write" else [*read, *write]
    if resolved is not None and any(
        root is not None and is_within(resolved, root)
        for root in map(canonicalize_path, entries)
    ):
        return resolved, None
    return None, "outside_write" if access == "write" else "outside_read"
