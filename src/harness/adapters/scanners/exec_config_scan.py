"""exec_config_scan.py — executable-field scanner for structured configuration.

Detects configuration that turns into execution: an agent bundle whose adapter
runs a process, a job spec with a command field, a lifecycle hook. The signal
is the *structure* of a parsed YAML or JSON document — which keys sit where —
not the words in it, so a plain `command: ./run.sh` is seen even though no
shell-text scanner has anything to say about it.

Runs at any boundary and is part of the recommended list at scan_input,
scan_tool_result and scan_file, and the gate's argument scanners by default.
Text that does not parse as a document yields no findings.

No `.l10n.yaml` sibling, deliberately: executable field names are not
translated, so unlike every pattern catalog in this package this scanner has
exactly one copy. Its absence is not the gap the five-copy rule exists to
catch.

Findings carry rule ids only. Keys, values and commands never reach
`Finding.detail` (Invariant 3). A candidate that holds a command or hook key but
passes a parser limit (size, document count, depth, node count) reports the
advisory `exec_config.limit_exceeded` rather than nothing.
"""
from __future__ import annotations

import json
import logging
import re
from collections import deque
from typing import Any

import yaml

from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding

log = logging.getLogger(__name__)


# ── Vocabulary ────────────────────────────────────────────────────────────
# Keys are compared lowercased with `_`, `-` and whitespace removed. This is
# the initial list; extending it is a one-line change here.

_COMMAND_KEYS = frozenset({
    "command", "cmd", "exec", "entrypoint", "script", "shell", "run",
})
_PROCESS_MARKER_KEYS = frozenset({"adapter", "type", "kind"})
_PROCESS_MARKER_VALUES = frozenset({
    "process", "shell", "exec", "subprocess", "command",
})
_HOOK_KEYS = frozenset({
    "hooks", "lifecycle", "prestart", "poststart", "preinstall",
    "postinstall", "onstart", "setup",
})

# Pipelines, command chaining, substitution, redirection. A plain pattern, not
# a shell parse: this scanner is always on and must not need the `shell` extra.
_METACHARACTERS = re.compile(r"[|;&<>`]|\$\(")

_FENCE_RE = re.compile(r"```[ \t]*(?:ya?ml|json)[^\n]*\n(.*?)```", re.DOTALL | re.IGNORECASE)

# A candidate is parsed only if it holds one of the command or hook keys as a
# key. Process markers alone never produce a finding (a command is required),
# so this keeps the YAML parser off the overwhelming majority of text.
_KEY_HINT = re.compile(
    r"(?:command|cmd|exec|entry[-_ ]?point|script|shell|run|hooks|lifecycle"
    r"|(?:pre|post)[-_ ]?(?:start|install)|on[-_ ]?start|setup)[\"']?\s*:",
    re.IGNORECASE,
)

# The gate hands a scanner each argument as `<name>: <value>`; that label makes
# a block document unparseable, so the value is also tried on its own.
_FRAME_RE = re.compile(r"^[\w.\-]+:[ \t]+(?=\S)")

# Cost ceilings. A scanner on the input path must not be a parse-bomb target.
_MAX_CHARS = 200_000
_MAX_DOCUMENTS = 16
_MAX_NODES = 10_000
_MAX_DEPTH = 32
_MAX_CANDIDATES = 8


def _norm(key: Any) -> str:
    return re.sub(r"[\s_\-]", "", str(key)).lower()


def _has_text(value: Any) -> bool:
    """A command-shaped value: a non-empty string, or a list holding one."""
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(isinstance(v, str) and v.strip() for v in value)
    return False


def _command_text(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(v for v in value if isinstance(v, str))
    return value if isinstance(value, str) else ""


def _documents(candidate: str) -> tuple[list[Any], bool]:
    """Parse one candidate into at most _MAX_DOCUMENTS documents.

    Returns the documents and whether a limit cut the examination short. Text
    that is simply not a document is `([], False)`; a candidate too large, too
    many documents, or nested past the parser's recursion limit is a limit.
    """
    if len(candidate) > _MAX_CHARS:
        return [], True
    if candidate.lstrip().startswith(("{", "[")):
        try:
            return [json.loads(candidate)], False
        except RecursionError:
            pass  # yaml below reaches the same limit and reports it
        except ValueError:
            log.debug("exec_config_scan: not JSON, trying YAML")
    docs: list[Any] = []
    try:
        for doc in yaml.safe_load_all(candidate):
            if len(docs) == _MAX_DOCUMENTS:
                return docs, True
            docs.append(doc)
    except RecursionError:
        return [], True
    except (yaml.YAMLError, ValueError):
        log.debug("exec_config_scan: candidate is not a YAML document")
        return [], False
    return docs, False


def _candidates(text: str) -> list[str]:
    """The whole text, the text after a leading `name: ` label, then each fenced
    yaml/json block inside it."""
    out = [text]
    framed = _FRAME_RE.match(text)
    if framed:
        out.append(text[framed.end():])
    out.extend(m.group(1) for m in _FENCE_RE.finditer(text))
    return out[:_MAX_CANDIDATES]


def _walk(root: Any, rules: dict[str, Severity]) -> bool:
    """Breadth-first over mappings and lists, recording rule ids into `rules`.

    Shared (aliased) containers are visited once, so alias expansion cannot
    multiply the work; the node and depth caps bound what remains. Returns True
    when a cap left part of the document unexamined.
    """
    truncated = False
    # Per-mapping records, indexed in discovery order: parent mapping index, has
    # process marker, has a command field directly. Subtree command presence is
    # folded upward afterwards.
    parents: list[int] = []
    marker: list[bool] = []
    direct_cmd: list[bool] = []

    seen: set[int] = set()
    queue: deque[tuple[Any, int, int]] = deque([(root, -1, 0)])
    visited = 0
    while queue:
        node, parent, depth = queue.popleft()
        if not isinstance(node, (dict, list)) or id(node) in seen:
            continue
        if depth > _MAX_DEPTH:
            truncated = True
            continue
        seen.add(id(node))
        visited += 1
        if visited > _MAX_NODES:
            truncated = True
            break

        if isinstance(node, list):
            queue.extend((v, parent, depth + 1) for v in node)
            continue

        index = len(parents)
        parents.append(parent)
        is_marker = False
        has_cmd = False
        for key, value in node.items():
            nk = _norm(key)
            if nk in _PROCESS_MARKER_KEYS and isinstance(value, str) \
                    and _norm(value) in _PROCESS_MARKER_VALUES:
                is_marker = True
            if nk in _COMMAND_KEYS and _has_text(value):
                has_cmd = True
                _record(rules, "command_field", Severity.MEDIUM)
                if _METACHARACTERS.search(_command_text(value)):
                    _record(rules, "command_metacharacters", Severity.HIGH)
            if nk in _HOOK_KEYS and value:
                _record(rules, "lifecycle_hook", Severity.MEDIUM)
            queue.append((value, index, depth + 1))
        marker.append(is_marker)
        direct_cmd.append(has_cmd)

    subtree_cmd = list(direct_cmd)
    for i in range(len(parents) - 1, 0, -1):
        if subtree_cmd[i] and parents[i] >= 0:
            subtree_cmd[parents[i]] = True

    for i, is_marker in enumerate(marker):
        if not is_marker:
            continue
        # The command is under the marker's mapping, or sits directly beside a
        # marker held in a child mapping (`adapter: {type: process}`). Commands
        # deeper in the parent's other branches belong to something else.
        if subtree_cmd[i] or (parents[i] >= 0 and direct_cmd[parents[i]]):
            _record(rules, "process_adapter", Severity.HIGH)
            break
    return truncated


def _record(rules: dict[str, Severity], rule: str, severity: Severity) -> None:
    prior = rules.get(rule)
    if prior is None or severity > prior:
        rules[rule] = severity


class ExecConfigScanner:
    """Executable-configuration scanner. Satisfies the Scanner Protocol."""

    name = "exec_config_scan"
    method_family = "structural_config"
    # Reads indentation and line breaks, which the surface view collapses; see
    # core.normalize.wants_layout.
    wants_layout = True

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        if not text or not text.strip():
            return ScanResult()

        rules: dict[str, Severity] = {}
        for candidate in _candidates(text):
            if not _KEY_HINT.search(candidate):
                continue
            docs, limited = _documents(candidate)
            for doc in docs:
                limited = _walk(doc, rules) or limited
            if limited:
                # Advisory, like normalization's budget_exhausted: "partly
                # examined" must not look the same as "nothing to find", and a
                # bundle padded past a limit is itself anomalous.
                _record(rules, "limit_exceeded", Severity.MEDIUM)
                log.debug("exec_config_scan reached a parser limit")

        if not rules:
            return ScanResult()

        log.debug(
            "executable configuration fields detected",
            extra={"rules": sorted(rules), **ctx.to_log_fields()},
        )
        return ScanResult(findings=[
            Finding(
                scanner=self.name,
                category=f"exec_config.{rule}",
                severity=severity,
                detail=f"executable configuration field: {rule}",
            )
            for rule, severity in sorted(rules.items())
        ])
