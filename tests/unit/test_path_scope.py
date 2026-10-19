"""Tests for core/path_scope.py."""
import os

import pytest

from harness.core.path_scope import is_absolute, is_within


@pytest.mark.parametrize("p", ["/srv/x", "/"])
def test_slash_rooted_forms_are_absolute(p):
    assert is_absolute(p)


@pytest.mark.skipif(os.sep != "\\", reason="Windows path forms")
@pytest.mark.parametrize("p", [r"\srv\x", r"C:\x", "C:/x", r"\\host\share\x"])
def test_windows_rooted_forms_are_absolute(p):
    assert is_absolute(p)


@pytest.mark.parametrize("p", ["x", "a/b", "../x", ""])
def test_unrooted_forms_are_not_absolute(p):
    assert not is_absolute(p)


@pytest.mark.skipif(os.sep != "\\", reason="drive-relative is a Windows form")
def test_drive_relative_is_not_absolute():
    assert not is_absolute("C:x")


def test_within_equal_and_beneath():
    assert is_within("/data", "/data")
    assert is_within("/data/a/b", "/data")
    assert is_within("/data/", "/data")


def test_sibling_prefix_is_not_within():
    assert not is_within("/data-evil", "/data")
    assert not is_within("/data-evil/x", "/data")


def test_dot_segments_collapse():
    assert is_within("/data/./a", "/data")
    assert is_within("/data/a/../b", "/data")
    assert not is_within("/data/../etc", "/data")


def test_root_contains_everything_absolute():
    assert is_within("/anything/at/all", "/")
