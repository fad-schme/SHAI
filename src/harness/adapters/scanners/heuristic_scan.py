"""heuristic_scan.py — structural anomaly scanner.

Always on — appended by _build_text_scanners when not explicitly declared.
Declaring it in harness.yaml only controls its position and per-scanner action.
Catches patterns regex catalogs miss: obfuscated payloads, instruction-dense
text, register shifts, and embedded markup in natural language.

Four sub-scores (each 0–2). Sum ≥ 5 → HIGH, ≥ 3 → MEDIUM, ≥ 1 → LOW.
No dependencies. No ML.
"""
from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

from harness.adapters.scanners.base import ScanResult, SeverityScale
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding

# Raised from 4.5 → 4.8: natural dense English (code comments, tables, URLs)
# brushes 4.5 over a 64-char window and produced low-grade false positives.
# base64/hex payloads sit well above 5.0, so recall on real obfuscation is
# unaffected.
_ENTROPY_THRESHOLD = 4.8
_ENTROPY_WINDOW = 64
_DENSITY_THRESHOLD = 0.08

_CONTROL_TOKENS = frozenset({
    # imperative / override verbs
    "ignore", "override", "forget", "disregard", "bypass", "skip",
    "instead", "always", "never", "must", "execute", "run", "call",
    "output", "print", "reveal", "repeat", "respond", "pretend",
    # agentic action verbs — tool coercion and exfiltration surface
    "invoke", "fetch", "download", "upload", "send", "forward", "export",
    "delete", "disable", "enable", "grant", "escalate", "elevate",
    "leak", "exfiltrate", "transmit", "post", "curl", "wget",
    # instruction-framing tokens
    "system", "assistant", "instructions", "prompt", "act", "simulate",
})

_STRUCTURAL_RE = re.compile(
    r"<\|(?:system|user|assistant|im_start|im_end)\|>"
    r"|\[/?INST\]"
    r"|<<SYS>>|<</SYS>>"
    r"|\[(?:system|assistant|user)\]\s*[:>]"
    r"|### (?:Instruction|System|Response)"
    r"|```(?:system|tool_call)"
    r"|</?(?:system|tool_use|function_call|result)>"
    r"|\{\"(?:role|function|tool_calls)\":",
    re.IGNORECASE,
)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _entropy_score(text: str) -> float:
    """0–2: sliding window entropy over the text."""
    if len(text) < _ENTROPY_WINDOW:
        e = _shannon_entropy(text)
        return min(2.0, max(0.0, (e - _ENTROPY_THRESHOLD) * 2.0)) if e > _ENTROPY_THRESHOLD else 0.0
    max_e = 0.0
    for i in range(0, len(text) - _ENTROPY_WINDOW + 1, _ENTROPY_WINDOW // 2):
        e = _shannon_entropy(text[i : i + _ENTROPY_WINDOW])
        if e > max_e:
            max_e = e
    if max_e <= _ENTROPY_THRESHOLD:
        return 0.0
    return min(2.0, (max_e - _ENTROPY_THRESHOLD) * 2.0)


def _instruction_density_score(text: str) -> float:
    """0–2: ratio of control tokens to total tokens."""
    tokens = text.lower().split()
    if len(tokens) < 5:
        return 0.0
    hits = sum(1 for t in tokens if t.rstrip(".:,;!?") in _CONTROL_TOKENS)
    density = hits / len(tokens)
    if density <= _DENSITY_THRESHOLD:
        return 0.0
    return min(2.0, (density - _DENSITY_THRESHOLD) / _DENSITY_THRESHOLD * 2.0)


def _coherence_score(text: str) -> float:
    """0–2: bigram divergence between first and second half."""
    normalized = unicodedata.normalize("NFKC", text).lower()
    if len(normalized) < 40:
        return 0.0
    mid = len(normalized) // 2
    first = Counter(normalized[i : i + 2] for i in range(mid - 1))
    second = Counter(normalized[i : i + 2] for i in range(mid, len(normalized) - 1))
    all_bg = set(first) | set(second)
    if not all_bg:
        return 0.0
    intersection = sum(min(first[b], second[b]) for b in all_bg)
    union = sum(max(first[b], second[b]) for b in all_bg)
    divergence = 1.0 - (intersection / union if union else 1.0)
    if divergence < 0.6:
        return 0.0
    return min(2.0, (divergence - 0.6) * 5.0)


def _structural_score(text: str) -> float:
    """0–2: count of embedded markup patterns."""
    matches = _STRUCTURAL_RE.findall(text)
    if not matches:
        return 0.0
    return min(2.0, len(matches) * 0.7)


# ── Typoglycemia sub-score ────────────────────────────────────────────────
# OWASP LLM Prompt Injection Prevention cheat sheet lists typoglycemia as a
# distinct attack class (arxiv.org/abs/2410.01677): scrambled keywords like
# "ignroe / prevoius / delte / revael" that literal regex catalogs cannot see
# because they compare against exact spellings. Handled here as a heuristic
# sub-score so it runs on every text regardless of catalog match.
#
_TYPO_ACTIONS = frozenset({
    "ignore", "override", "bypass", "reveal", "disable", "delete", "exfiltrate",
    "exfil", "disregard", "forget", "expose", "leak", "escalate", "elevate",
    "cancel", "remove", "eliminate", "circumvent", "suspend", "deactivate",
    "grant", "forward", "execute", "turn",
})

_TYPO_PROTECTED_OBJECTS = frozenset({
    "instruction", "instructions", "prompt", "system", "safety", "filter",
    "filters", "restriction", "restrictions", "credential", "credentials",
    "admin", "guardrail", "guardrails", "security", "policy", "password",
    "passwords", "secret", "secrets", "alignment", "context",
    "programming", "conversation", "transcript", "transcripts",
})

_TYPO_EXECUTION_DESTINATIONS = frozenset({
    "attacker", "external", "email", "webhook", "shell", "account", "url",
})

_LEETSPEAK_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
})

_FRAGMENTED_TOKEN_RE = re.compile(r"\b(?:[a-z0-9][.-]){3,}[a-z0-9]\b")
_SEPARATOR_CHAIN_RE = re.compile(r"\b(?:[a-z0-9]{3,}[.-]){3,}[a-z0-9]{3,}\b")
_RAW_FUZZY_TOKEN_RE = re.compile(r"[a-z0-9]{4,}")
_FUZZY_TOKEN_RE = re.compile(r"[a-z]{4,}")


@dataclass(frozen=True)
class _FuzzyIntent:
    score: float
    actions: frozenset[str]
    protected_objects: frozenset[str]
    execution_destinations: frozenset[str]
    has_obfuscation: bool

    @property
    def is_compound_attack(self) -> bool:
        return bool(self.actions and self.protected_objects and self.has_obfuscation)


def _bounded_dl_distance(a: str, b: str, limit: int) -> int | None:
    """Bounded optimal-string-alignment distance, including transpositions."""
    if abs(len(a) - len(b)) > limit:
        return None

    previous_previous: list[int] | None = None
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        row_min = i
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            distance = min(
                current[j - 1] + 1,
                previous[j] + 1,
                previous[j - 1] + cost,
            )
            if (
                previous_previous is not None
                and i > 1
                and j > 1
                and char_a == b[j - 2]
                and a[i - 2] == char_b
            ):
                distance = min(distance, previous_previous[j - 2] + 1)
            current.append(distance)
            row_min = min(row_min, distance)
        if row_min > limit:
            return None
        previous_previous, previous = previous, current

    return previous[-1] if previous[-1] <= limit else None


def _typoglycemia_match_kind(word: str, target: str) -> str | None:
    """Return ``strong`` or ``weak`` when word is a bounded fuzzy variant.

    Anagram-style scramble (same length, same first + last letter, sorted
    middle equal) OR bounded Damerau-Levenshtein distance with the additional
    constraint that neither word is a prefix of the other. The prefix check
    rejects English morphological forms — every real typoglycemia example
    changes the middle of the word (`ignroe`, `delte`, `ovverride`,
    `securty`), while every morphological variant appends at the end
    (`ignored`, `filters`, `systems`, `disabled`). Rejecting prefix pairs
    eliminates a whole class of false positives without weakening the
    attack signal.

    Word must be at least length 4 to reduce noise on short tokens.
    """
    if len(word) < 4 or len(target) < 4:
        return None
    if word == target:
        return None
    # Anagram scramble — cheap, catches the OWASP-cited pattern
    if (len(word) == len(target)
            and word[0] == target[0] and word[-1] == target[-1]
            and sorted(word[1:-1]) == sorted(target[1:-1])):
        return "strong"
    distance_limit = 2 if min(len(word), len(target)) >= 7 else 1
    if _bounded_dl_distance(word, target, distance_limit) is None:
        return None
    # Prefix-relationship rejection: one is the other + trailing chars →
    # morphological form, not typoglycemia.
    if word.startswith(target):
        return None
    # Insertions/deletions are strong obfuscation evidence. Same-length
    # substitutions can collide with ordinary words ("peak" → "leak",
    # "content" → "context"), so they are weak and need corroborating fuzzy
    # evidence from both the action and object classes.
    return "strong" if len(word) != len(target) else "weak"


def _normalize_fuzzy_text(text: str) -> tuple[list[str], frozenset[str]]:
    normalized = unicodedata.normalize("NFKC", text).lower()
    transformed_tokens: set[str] = set()

    for original_token in re.findall(r"[A-Za-z]{4,}", text):
        uppercase_count = sum(char.isupper() for char in original_token)
        lowercase_count = sum(char.islower() for char in original_token)
        if uppercase_count >= 2 and lowercase_count >= 2:
            transformed_tokens.add(original_token.lower())

    def join_fragment(match: re.Match[str]) -> str:
        joined = match.group(0).replace(".", "").replace("-", "")
        translated_joined = joined.translate(_LEETSPEAK_TRANSLATION)
        transformed_tokens.add(translated_joined)
        return joined

    joined = _FRAGMENTED_TOKEN_RE.sub(join_fragment, normalized)
    for chain in _SEPARATOR_CHAIN_RE.findall(joined):
        transformed_tokens.update(
            part.translate(_LEETSPEAK_TRANSLATION)
            for part in re.split(r"[.-]+", chain)
        )

    for raw_token in _RAW_FUZZY_TOKEN_RE.findall(joined):
        translated_token = raw_token.translate(_LEETSPEAK_TRANSLATION)
        if translated_token != raw_token:
            transformed_tokens.add(translated_token)

    translated = joined.translate(_LEETSPEAK_TRANSLATION)
    separated = re.sub(r"(?<=[a-z0-9])[.-]+(?=[a-z0-9])", " ", translated)
    return _FUZZY_TOKEN_RE.findall(separated), frozenset(transformed_tokens)


def _match_fuzzy_class(
    tokens: list[str],
    targets: frozenset[str],
    transformed_tokens: frozenset[str],
) -> tuple[frozenset[str], bool, bool, int]:
    matched: set[str] = set()
    fuzzy_targets: set[str] = set()
    fuzzy = False
    strong = False
    for token in tokens:
        if token in targets:
            matched.add(token)
            if token in transformed_tokens:
                fuzzy = True
                strong = True
                fuzzy_targets.add(token)
            continue
        # A token can fuzzy-match several targets. Two rules decide which one
        # is recorded, and both matter:
        #
        # Order — `targets` is a frozenset, and set iteration order for strings
        # varies with PYTHONHASHSEED, so taking whichever match appeared first
        # made the classification differ between processes on byte-identical
        # input. Sorting fixes the order; the cost is trivial on vocabularies
        # this size.
        #
        # Strength — a weak (same-length substitution) match found first used
        # to suppress a strong match on another target, which was arbitrary
        # rather than a judgement. Strong wins wherever it appears, and is
        # still short-circuited because nothing beats it.
        best_target: str | None = None
        best_kind: str | None = None
        for target in sorted(targets):
            if abs(len(token) - len(target)) > 2:
                continue
            match_kind = _typoglycemia_match_kind(token, target)
            if match_kind is None:
                continue
            if match_kind == "strong":
                best_target, best_kind = target, "strong"
                break
            if best_target is None:
                best_target, best_kind = target, match_kind

        if best_target is not None:
            matched.add(best_target)
            fuzzy = True
            strong = strong or best_kind == "strong"
            fuzzy_targets.add(best_target)
    return frozenset(matched), fuzzy, strong, len(fuzzy_targets)


def _fuzzy_intent(text: str) -> _FuzzyIntent:
    """Classify fuzzy action, protected-object, and destination evidence."""
    tokens, transformed_tokens = _normalize_fuzzy_text(text)
    actions, fuzzy_actions, strong_actions, action_fuzzy_count = _match_fuzzy_class(
        tokens,
        _TYPO_ACTIONS,
        transformed_tokens,
    )
    protected, fuzzy_protected, strong_protected, protected_fuzzy_count = _match_fuzzy_class(
        tokens,
        _TYPO_PROTECTED_OBJECTS,
        transformed_tokens,
    )
    destinations, fuzzy_destinations, strong_destinations, destination_fuzzy_count = (
        _match_fuzzy_class(
            tokens,
            _TYPO_EXECUTION_DESTINATIONS,
            transformed_tokens,
        )
    )
    # Corroboration for weak (same-length substitution) matches must come from
    # *within one class*, not across classes.
    #
    # Two corrupted protected-object keywords in one message is a deliberate
    # pattern — "ynstructions" and "systym" together are not a coincidence.
    # One weak match in each of two different classes is: `content` collides
    # with `context` and `attached` with `attacker`, so an ordinary email
    # ("please ignore the previous email … the correct version is attached")
    # inside any JSON carrying a `content` field scored as a compound
    # typoglycemia attack at HIGH.
    #
    # Summing across classes, and the cross-class `fuzzy_actions and
    # fuzzy_protected` pairing, both let two accidental real-word collisions
    # corroborate each other. Neither can tell deliberate corruption from a
    # coincidental near-miss, because that distinction is lexical and this
    # scanner has no dictionary. Requiring the repetition within a single
    # class is the discriminator available without one.
    #
    # Destinations are excluded from the weak-match count. That vocabulary is
    # short common nouns — email, account, url, shell — with dense real-word
    # neighbourhoods, so two *accidental* collisions land in it easily:
    # `gmail` is one substitution from `email` and `attached` two from
    # `attacker`, which made an ordinary Gmail tool result ("the new ones are
    # attached, sent from gmail") a compound attack. Actions and protected
    # objects are longer, more specific words where repetition is real signal.
    # A *strong* destination match still counts on its own — a scrambled
    # `webhook` is evidence; a near-miss on `email` is not.
    #
    # ACCEPTED GAP: dropping the cross-class pairing means exactly two
    # same-length corruptions, one action and one protected object, no longer
    # register — "ignoer the systym prompt" passes. A third corrupted word, or
    # any insertion/deletion (which scores `strong`), restores detection. The
    # trade is deliberate: the pairing fired on ordinary email traffic, and
    # this evasion needs a precise two-word construction. Pinned by
    # tests/unit/test_typoglycemia_corroboration.py::TestAcceptedEvasion.
    has_obfuscation = (
        strong_actions
        or strong_protected
        or strong_destinations
        or max(action_fuzzy_count, protected_fuzzy_count) >= 2
    )
    # Scoring consults has_obfuscation rather than recomputing a bar beside it.
    # A lone weak match otherwise contributed 0.8 on its own, and that mattered
    # far beyond typos: `content` is one substitution from `context`, so any
    # tool result with a `content` field scored 0.8, which in turn unlocked the
    # gated coherence sub-score (JSON is not prose) and produced a LOW
    # heuristic_anomaly on ordinary structured tool output.
    fuzzy_evidence_count = sum((fuzzy_actions, fuzzy_protected, fuzzy_destinations))
    score = min(2.0, fuzzy_evidence_count * 0.8) if has_obfuscation else 0.0
    if actions and protected and has_obfuscation:
        score = max(score, 2.0)
    return _FuzzyIntent(
        score=score,
        actions=actions,
        protected_objects=protected,
        execution_destinations=destinations,
        has_obfuscation=has_obfuscation,
    )


def _fuzzy_intent_score(text: str) -> float:
    """Return the fuzzy-intent contribution to the anomaly score."""
    return _fuzzy_intent(text).score


class HeuristicScanner:
    """Structural anomaly scanner. Always on. Satisfies Scanner Protocol."""

    name = "heuristic_scan"
    method_family = "structural_heuristic"
    # Floor of 1.0: below it the sub-scores are noise, and no
    # heuristic_anomaly finding is emitted. A compound typoglycemia
    # attack is reported separately and does not consult the scale.
    SCALE = SeverityScale(high=5.0, medium=3.0, floor=1.0)

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        if not text or not text.strip():
            return ScanResult()

        s1 = _entropy_score(text)
        s2 = _instruction_density_score(text)
        s3 = _coherence_score(text)
        s4 = _structural_score(text)
        fuzzy_intent = _fuzzy_intent(text)
        s5 = fuzzy_intent.score

        # Coherence (bigram register-shift) is the weakest sub-score and fires
        # on benign transitions (prose → code block, English → citation). It is
        # only trustworthy as corroboration, so it contributes only when at
        # least one stronger signal is already nonzero.
        if s1 == 0.0 and s2 == 0.0 and s4 == 0.0 and s5 == 0.0:
            s3 = 0.0

        total = s1 + s2 + s3 + s4 + s5

        # None below the scale's floor — the same 1.0 that decides whether a
        # heuristic_anomaly finding is emitted at all, expressed once.
        severity = self.SCALE.severity_for(total)

        if severity is None and not fuzzy_intent.is_compound_attack:
            return ScanResult()

        # The authoritative copy of the sub-scores. `detail` below renders the
        # same numbers for a human; consumers read these. Every finding this
        # scanner emits carries them, so a consumer never has to pick the right
        # one out of the list to get a complete picture.
        signals = {
            "entropy":      s1,
            "density":      s2,
            "coherence":    s3,
            "structural":   s4,
            "fuzzy_intent": s5,
            "total":        total,
        }

        parts = []
        if s1 > 0:
            parts.append(f"entropy={s1:.1f}")
        if s2 > 0:
            parts.append(f"density={s2:.1f}")
        if s3 > 0:
            parts.append(f"coherence={s3:.1f}")
        if s4 > 0:
            parts.append(f"structural={s4:.1f}")
        if s5 > 0:
            parts.append(f"fuzzy_intent={s5:.1f}")

        findings: list[Finding] = []
        if fuzzy_intent.is_compound_attack:
            action_names = ",".join(sorted(fuzzy_intent.actions))
            object_names = ",".join(sorted(fuzzy_intent.protected_objects))
            detail = f"fuzzy compound: actions={action_names}; protected_objects={object_names}"
            if fuzzy_intent.execution_destinations:
                destinations = ",".join(sorted(fuzzy_intent.execution_destinations))
                detail += f"; execution_destinations={destinations}"
            findings.append(Finding(
                scanner=self.name,
                category="typoglycemia_compound",
                severity=Severity.HIGH,
                detail=detail,
                signals=signals,
            ))

        if severity is not None:
            findings.append(Finding(
                scanner=self.name,
                category="heuristic_anomaly",
                severity=severity,
                detail=f"total={total:.1f} ({', '.join(parts)})",
                signals=signals,
            ))

        return ScanResult(findings=findings)
