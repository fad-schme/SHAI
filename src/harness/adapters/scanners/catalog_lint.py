"""Strict validation for YAML regex catalogs.

Every rule must declare its match expression and classification metadata.
The linter also validates compound references and rejects regex shapes that
commonly turn an intended phrase into a standalone-word match.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_REQUIRED_META = ("severity", "category", "threat_level")
_VALID_SEVERITIES = {"low", "medium", "high"}
_COMMON_SINGLE_WORDS = (
    "admin",
    "assistant",
    "call",
    "developer",
    "email",
    "instruction",
    "instructions",
    "invoke",
    "prompt",
    "send",
    "system",
    "tool",
    "use",
    "user",
)


@dataclass(frozen=True)
class CatalogLintIssue:
    code: str
    rule: str
    signal: str | None
    message: str

    def __str__(self) -> str:
        location = self.rule
        if self.signal:
            location += f".{self.signal}"
        return f"[{self.code}] {location}: {self.message}"


def _has_top_level_alternation(pattern: str) -> bool:
    """Detect an ungrouped ``|`` while respecting escapes and character sets."""
    depth = 0
    in_class = False
    escaped = False
    for char in pattern:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "[" and not in_class:
            in_class = True
            continue
        if char == "]" and in_class:
            in_class = False
            continue
        if in_class:
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "|" and depth == 0:
            return True
    return False


def _has_empty_alternative(pattern: str) -> bool:
    """Return true for empty branches such as ``(?:foo|)`` or ``|foo``."""
    if re.search(r"(?<!\\)\|\s*$|^\s*\|", pattern):
        return True
    if re.search(r"(?<!\\)\|\s*(?<!\\)\)", pattern):
        return True
    return re.search(r"(?<!\\)\((?:\?(?:[:=!]|<[=!])|[a-zA-Z-]+:)?\s*\|", pattern) is not None


def _lint_match(
    rule_name: str,
    strings: dict[str, Any],
    match: Any,
) -> list[CatalogLintIssue]:
    issues: list[CatalogLintIssue] = []
    if match == "any":
        return issues
    if not isinstance(match, dict) or not isinstance(match.get("all"), list):
        return [
            CatalogLintIssue(
                "invalid-match",
                rule_name,
                None,
                "match must be 'any' or a mapping containing a non-empty all list",
            )
        ]

    groups = match["all"]
    if not groups:
        issues.append(
            CatalogLintIssue(
                "invalid-match",
                rule_name,
                None,
                "match.all must contain at least one signal group",
            )
        )
        return issues

    within_chars = match.get("within_chars")
    if within_chars is not None and (
        not isinstance(within_chars, int)
        or isinstance(within_chars, bool)
        or not 1 <= within_chars <= 1000
    ):
        issues.append(
            CatalogLintIssue(
                "invalid-match",
                rule_name,
                None,
                "match.within_chars must be an integer from 1 to 1000",
            )
        )

    seen_names: set[str] = set()
    seen_references: set[str] = set()
    for index, group in enumerate(groups, start=1):
        signal = f"match.all[{index}]"
        if not isinstance(group, dict):
            issues.append(
                CatalogLintIssue("invalid-match", rule_name, signal, "group must be a mapping")
            )
            continue
        group_name = group.get("name")
        if group_name is not None:
            if not isinstance(group_name, str) or not group_name.strip():
                issues.append(
                    CatalogLintIssue(
                        "invalid-match", rule_name, signal, "name must be a non-empty string"
                    )
                )
            elif group_name in seen_names:
                issues.append(
                    CatalogLintIssue(
                        "duplicate-group",
                        rule_name,
                        signal,
                        f"signal-group name {group_name!r} is repeated",
                    )
                )
            else:
                seen_names.add(group_name)

        references = group.get("any")
        if not isinstance(references, list) or not references:
            issues.append(
                CatalogLintIssue(
                    "invalid-match",
                    rule_name,
                    signal,
                    "any must be a non-empty list of named signals",
                )
            )
            continue
        for reference in references:
            if not isinstance(reference, str) or reference not in strings:
                issues.append(
                    CatalogLintIssue(
                        "unknown-signal",
                        rule_name,
                        signal,
                        f"references undefined signal {reference!r}",
                    )
                )
            elif reference in seen_references:
                issues.append(
                    CatalogLintIssue(
                        "duplicate-signal",
                        rule_name,
                        signal,
                        f"signal {reference!r} is reused across all-groups",
                    )
                )
            else:
                seen_references.add(reference)
    return issues


def lint_catalog(data: Any) -> list[CatalogLintIssue]:
    """Return all catalog authoring problems without raising."""
    if not isinstance(data, dict) or not isinstance(data.get("patterns"), list):
        return [
            CatalogLintIssue(
                "invalid-catalog",
                "<catalog>",
                None,
                "top level must be a mapping containing a patterns list",
            )
        ]

    issues: list[CatalogLintIssue] = []
    for index, rule in enumerate(data["patterns"], start=1):
        if not isinstance(rule, dict):
            issues.append(
                CatalogLintIssue(
                    "invalid-rule", f"<rule-{index}>", None, "rule must be a mapping"
                )
            )
            continue

        rule_name = str(rule.get("name", f"<rule-{index}>"))
        meta = rule.get("meta")
        if not isinstance(meta, dict):
            meta = {}
        for field in _REQUIRED_META:
            if field not in meta:
                issues.append(
                    CatalogLintIssue(
                        "missing-meta",
                        rule_name,
                        None,
                        f"meta.{field} is required",
                    )
                )
        severity = meta.get("severity")
        if severity is not None and severity not in _VALID_SEVERITIES:
            issues.append(
                CatalogLintIssue(
                    "invalid-meta",
                    rule_name,
                    None,
                    "meta.severity must be low, medium, or high",
                )
            )
        category = meta.get("category")
        if category is not None and (not isinstance(category, str) or not category.strip()):
            issues.append(
                CatalogLintIssue(
                    "invalid-meta", rule_name, None, "meta.category must be a non-empty string"
                )
            )
        threat_level = meta.get("threat_level")
        if threat_level is not None and (
            not isinstance(threat_level, int)
            or isinstance(threat_level, bool)
            or not 1 <= threat_level <= 5
        ):
            issues.append(
                CatalogLintIssue(
                    "invalid-meta",
                    rule_name,
                    None,
                    "meta.threat_level must be an integer from 1 to 5",
                )
            )

        strings = rule.get("strings")
        if not isinstance(strings, dict) or not strings:
            issues.append(
                CatalogLintIssue(
                    "invalid-strings",
                    rule_name,
                    None,
                    "strings must be a non-empty mapping of named signals",
                )
            )
            strings = {}

        if "match" not in rule:
            issues.append(
                CatalogLintIssue(
                    "missing-match",
                    rule_name,
                    None,
                    "match is required; use 'any' or an explicit all expression",
                )
            )
        else:
            issues.extend(_lint_match(rule_name, strings, rule["match"]))

        for signal_name, pattern in strings.items():
            if not isinstance(pattern, str):
                issues.append(
                    CatalogLintIssue(
                        "invalid-signal",
                        rule_name,
                        str(signal_name),
                        "signal pattern must be a string",
                    )
                )
                continue
            stripped = pattern.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                continue
            try:
                compiled = re.compile(stripped, re.MULTILINE)
            except re.error as exc:
                issues.append(
                    CatalogLintIssue(
                        "invalid-regex", rule_name, str(signal_name), str(exc)
                    )
                )
                continue

            if _has_top_level_alternation(stripped):
                issues.append(
                    CatalogLintIssue(
                        "bare-alternation",
                        rule_name,
                        str(signal_name),
                        "top-level alternation must be wrapped in a non-capturing group",
                    )
                )
            if compiled.search("") is not None or _has_empty_alternative(stripped):
                issues.append(
                    CatalogLintIssue(
                        "zero-width-alternative",
                        rule_name,
                        str(signal_name),
                        "pattern or one of its alternatives can match without consuming text",
                    )
                )
            if re.search(r"\\\\(?:[|[\]]|[bBdDsSwW])", stripped):
                issues.append(
                    CatalogLintIssue(
                        "invalid-escaping",
                        rule_name,
                        str(signal_name),
                        "double escaping changes a regex token into a literal backslash",
                    )
                )

            matched_words = [word for word in _COMMON_SINGLE_WORDS if compiled.fullmatch(word)]
            if matched_words:
                issues.append(
                    CatalogLintIssue(
                        "common-single-word",
                        rule_name,
                        str(signal_name),
                        f"pattern matches standalone common word(s): {', '.join(matched_words)}",
                    )
                )
    return issues
