"""Opening a file the gate approved, re-verified at the moment of use.

`SHAI.fs.open` resolves the path again and passes the resolved location here.
A final path component that became a link after that resolution is refused
instead of followed.
"""
from __future__ import annotations

import errno
import os
import stat
from typing import IO, Any

_LINK_ERRNOS = (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP))


class LinkRefused(Exception):
    """The final component of the path is a link."""


def _nofollow_opener(path: str, flags: int) -> int:
    if os.name == "nt":
        try:
            attrs = os.lstat(path).st_file_attributes
        except FileNotFoundError:
            attrs = 0
        if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise LinkRefused
    try:
        return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        if e.errno in _LINK_ERRNOS:
            raise LinkRefused from e
        raise


def open_resolved(resolved: str, mode: str, **kwargs: Any) -> IO[Any]:
    """`open(resolved, mode, **kwargs)` that refuses a final-component link.

    Raises LinkRefused for a link; any other OSError is the caller's ordinary
    file error.
    """
    return open(resolved, mode, opener=_nofollow_opener, **kwargs)  # noqa: SIM115
