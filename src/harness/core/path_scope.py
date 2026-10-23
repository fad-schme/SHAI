"""Path canonicalization and containment shared by agent grants, the protected
set and the gate.

Containment is decided on the identity form, never on a raw string prefix:
`/data-evil` is not inside `/data`. Identity folds case in exactly the
directories whose filesystem ignores it, so `DATA/f.txt` is `data/f.txt` on a
case-insensitive volume and a different file on a case-sensitive one.
`canonicalize_path` resolves symlinks; the identity form probes the filesystem
for case behaviour.
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


def _exists(path: str) -> bool:
    return os.path.lexists(path)


def _folds_case(parent: str, name: str) -> bool | None:
    """Whether `parent` ignores case, probed with the existing entry `name`:
    true when the case-swapped spelling is the same file. None when `name` has no
    letters to swap."""
    alt = name.swapcase()
    if alt == name:
        return None
    other = os.path.join(parent, alt)
    try:
        return _exists(other) and os.path.samefile(os.path.join(parent, name), other)
    except OSError:
        return False


def _identity(path: str) -> str:
    """`path` as the filesystem identifies it: normalized, with each component
    lowercased when its directory ignores case. A component that does not exist
    yet takes the case behaviour of the nearest existing ancestor, so a file
    about to be created compares like one that is there."""
    drive, rest = os.path.splitdrive(os.path.normpath(path))
    folds = os.path.normcase("A") != "A"
    current = drive + os.sep
    parts = []
    for name in (c for c in rest.split(os.sep) if c):
        if _exists(os.path.join(current, name)):
            probed = _folds_case(current, name)
            folds = folds if probed is None else probed
        parts.append(name.lower() if folds else name)
        current = os.path.join(current, name)
    return os.path.normcase(drive) + os.sep + os.sep.join(parts)


def _contains(path_id: str, root_id: str) -> bool:
    return path_id == root_id or path_id.startswith(root_id.rstrip(os.sep) + os.sep)


def is_within(path: str, root: str) -> bool:
    """True when `path` equals `root` or sits beneath it, comparing identity
    forms (separators unified, `.` and `..` collapsed, case folded where the
    filesystem folds it)."""
    return _contains(_identity(path), _identity(root))


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
    parent_read: Sequence[str] | None = None,
    parent_write: Sequence[str] | None = None,
) -> tuple[str | None, FsRule | None]:
    """Decide whether `value` may be used for `access`.

    Returns `(resolved, None)` when it may, and `(None, rule)` when it may
    not, `rule` naming which control refused it. A path in the protected set is
    refused whatever the grant says; otherwise it must sit inside a `write` entry
    (for write access) or a `read` or `write` entry (for read access). Grant
    entries are resolved with the same function as the value, so a symlinked
    root matches what it points to.

    A subagent passes its parent's grant as `parent_read` / `parent_write`: the
    path must then be inside both grants for the same access, each resolved on
    this call, so a subagent is never wider than its parent however a link
    changes after load. Both None (a parent context) checks `read` / `write` only.
    """
    resolved = canonicalize_path(value)
    if resolved is None:
        return None, "outside_write" if access == "write" else "outside_read"
    identity = _identity(resolved)
    if any(_contains(identity, _identity(p)) for p in protected):
        return None, "protected"
    grants = [(read, write)]
    if parent_read is not None or parent_write is not None:
        grants.append((parent_read or [], parent_write or []))
    if all(_granted(identity, access, r, w) for r, w in grants):
        return resolved, None
    return None, "outside_write" if access == "write" else "outside_read"


def _granted(identity: str, access: Literal["read", "write"],
             read: Sequence[str], write: Sequence[str]) -> bool:
    """Whether one grant covers `identity`: a `write` entry for write access, a
    `read` or `write` entry for read access."""
    entries = write if access == "write" else [*read, *write]
    return any(
        root is not None and _contains(identity, _identity(root))
        for root in map(canonicalize_path, entries)
    )
