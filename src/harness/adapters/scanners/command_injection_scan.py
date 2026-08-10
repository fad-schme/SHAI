"""command_injection_scan.py — shell command-injection scanner.

Detects command *composition*, not command vocabulary. The signals are AST
shapes — a pipeline whose sink is an interpreter, a redirect to /dev/tcp, a
fetch composed with an exec — because those carry to phrasings nobody
enumerated, while a deny-list of idioms only matches the idioms it lists.

Runs at any boundary: declare `command_injection_scan` under `scan_input`,
`scan_output`, `scan_tool_result`, `scan_file`, or `check_tool_call`. A user
can plant a command in input, a tool can return one in its result, and a file
can carry one in its body — the same shapes matter at every one of them, and
each boundary's own `block_at` decides what the severity means there.

No `.l10n.yaml` sibling, deliberately: shell syntax is language-independent,
so unlike every pattern catalog in this package this scanner has exactly one
copy. Its absence is not the gap the five-copy rule exists to catch.

Requires the `shell` extra (`pip install shai-harness[shell]`) for `bashlex`. Declaring
the scanner without it fails at from_yaml() rather than degrading silently — a
command scanner that quietly stopped parsing is worse than one that never ran.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.types import Severity
from harness.core.verdicts import Finding

try:
    import bashlex
except ImportError:  # pragma: no cover - exercised by the ConfigError path
    bashlex = None  # type: ignore[assignment]

log = logging.getLogger(__name__)


# ── Vocabulary ────────────────────────────────────────────────────────────
# These sets decide which lines are *parsed*, and which AST role a word plays.
# They are not the detection: a word from any of them, alone, is not a finding.

_INTERPRETERS = frozenset({
    "sh", "bash", "zsh", "ksh", "dash", "csh", "fish",
    "python", "python2", "python3", "perl", "ruby", "node", "php", "lua",
    "powershell", "pwsh", "cmd",
})

_FETCHERS = frozenset({"curl", "wget", "fetch", "aria2c", "scp", "rsync"})

_INLINE_CODE_FLAGS = frozenset({"-c", "-e", "-command", "--command", "-encodedcommand"})

# Tokens inside an inline-code payload that mean "and then execute something
# opaque" — the difference between `python -c "print(1)"` and a dropper.
_PAYLOAD_EXEC_TOKENS = re.compile(
    r"\b(?:exec|eval|system|popen|subprocess|socket|__import__|"
    r"base64|b64decode|fromcharcode|invoke-expression|iex)\b",
    re.IGNORECASE,
)

_DESTRUCTIVE = re.compile(
    r"^(?:rm|mkfs(?:\.\w+)?|shred|dd|chmod|chown|sudo|doas|killall)$",
    re.IGNORECASE,
)

# A line is parsed only if it mentions something worth parsing for. Keeps the
# parser off the overwhelming majority of text and bounds the cost of a scan.
_TRIGGER = re.compile(
    r"(?:\b(?:" + "|".join(sorted(_INTERPRETERS | _FETCHERS)) + r")\b)"
    r"|/dev/(?:tcp|udp)/"
    r"|\bchmod\b|\bchown\b|\bnc\b|\bncat\b|\bnetcat\b|\bmkfs\b|\bsudo\b|\bdoas\b"
    r"|\bdd\b|\brm\b|\bshred\b|\bkillall\b",
    re.IGNORECASE,
)

# Cost ceilings. A scanner on the input path must not be a parse-bomb target.
_MAX_CANDIDATES = 40
_MAX_LINE_CHARS = 2000

# Markdown scaffolding that would break the parse without changing the command.
_FENCE_RE = re.compile(r"^\s*```+\w*\s*$")
_PROMPT_RE = re.compile(r"^\s*(?:[$#>]\s+|\d+\.\s+|[-*]\s+)")

# An agent does not emit a bare shell line — it emits a *tool call* whose
# argument is the command: `run_shell('curl x | sh')`, `{"command": "wget …"}`.
# Parsing the enclosing line as shell sees only a quoted word, so the pipeline
# inside is invisible. These two shapes lift the quoted payload out as its own
# candidate.
#
# Both are structural: an identifier immediately followed by `(`, and a
# command-ish key bound to a string. Bare quotes in prose are deliberately not
# extracted — "the docs say 'curl x | sh'" is discussion, and the line-level
# candidate already covers it at the demoted severity.
_CALL_ARG_RE = re.compile(r"""\w+\s*\(\s*(['"])(?P<cmd>.+?)\1""")
_CMD_KEY_RE = re.compile(
    r"""["']?(?:command|cmd|script|shell|exec|run|entrypoint)["']?\s*[:=]\s*"""
    r"""(['"])(?P<cmd>.+?)\1""",
    re.IGNORECASE,
)

# A statement whose leading word is a program is an invocation; one that starts
# in prose is text discussing a command. Findings from the latter are demoted,
# never suppressed — an exclusion is attacker-writable (padding a payload with
# prose would erase it), whereas a demotion keeps the evidence in the audit
# trail and in TurnSignals, where a second signal in the turn can still
# escalate it. Note the failure direction: an unrecognised leading binary
# demotes, so this set can only cost severity, never detection.
_LEADING_BINARIES = _INTERPRETERS | _FETCHERS | frozenset({
    "echo", "printf", "cat", "env", "eval", "exec", "source", "chmod", "chown",
    "rm", "mv", "cp", "dd", "tar", "unzip", "base64", "openssl", "nc", "ncat",
    "netcat", "socat", "ssh", "sudo", "doas", "git", "docker", "kubectl",
    "apt", "apt-get", "yum", "brew", "npm", "npx", "pip", "pip3", "make",
})

_DEMOTE = {Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW}


def _is_invocation(word: str) -> bool:
    """True when a statement's leading word reads as a program, not prose."""
    return (
        _basename(word) in _LEADING_BINARIES
        or word.startswith(("./", "/", "~/"))
    )


# ── AST walk ──────────────────────────────────────────────────────────────

@dataclass
class _Facts:
    """What one parsed statement contains. Structure, never text."""
    commands:            list[list[str]] = field(default_factory=list)
    redirect_targets:    list[str]       = field(default_factory=list)
    pipe_to_interpreter: bool            = False


def _basename(word: str) -> str:
    return word.rsplit("/", 1)[-1].lower()


def _first_word(node: object) -> str | None:
    for part in getattr(node, "parts", []) or []:
        if getattr(part, "kind", None) == "word":
            return part.word
    return None


def _walk(node: object, facts: _Facts) -> None:
    kind = getattr(node, "kind", None)

    if kind == "command":
        words = [
            p.word for p in (getattr(node, "parts", []) or [])
            if getattr(p, "kind", None) == "word"
        ]
        if words:
            facts.commands.append(words)
        for part in getattr(node, "parts", []) or []:
            if getattr(part, "kind", None) == "redirect":
                target = getattr(part, "output", None)
                if hasattr(target, "word"):
                    facts.redirect_targets.append(target.word)

    elif kind == "pipeline":
        downstream = [
            p for p in (getattr(node, "parts", []) or [])
            if getattr(p, "kind", None) == "command"
        ][1:]
        for cmd in downstream:
            word = _first_word(cmd)
            if word and _basename(word) in _INTERPRETERS:
                facts.pipe_to_interpreter = True

    # Recurse into everything. Command substitution hangs off `.command`
    # rather than `.parts`, so a word like "$(curl x | sh)" is only reached
    # by following it — without this the payload hides one level down.
    for part in getattr(node, "parts", []) or []:
        _walk(part, facts)
    nested = getattr(node, "command", None)
    if nested is not None:
        _walk(nested, facts)


# ── Shape detection ───────────────────────────────────────────────────────

def _shapes(facts: _Facts) -> dict[str, Severity]:
    """Map shape name → severity for one parsed statement."""
    found: dict[str, Severity] = {}

    binaries = {_basename(words[0]) for words in facts.commands if words}

    if facts.pipe_to_interpreter:
        found["pipeline_to_interpreter"] = Severity.HIGH

    if any(t.startswith(("/dev/tcp/", "/dev/udp/")) for t in facts.redirect_targets):
        found["reverse_shell_redirect"] = Severity.HIGH

    fetches = bool(binaries & _FETCHERS)
    makes_executable = any(
        _basename(w[0]) == "chmod" and any(a.startswith("+") and "x" in a for a in w[1:])
        for w in facts.commands if w
    )
    # B108 flags hardcoded tmp paths. These are detection patterns matched
    # against text the scanner reads, not paths this process opens. A dropper
    # writes its payload to a world-writable directory and executes it from
    # there; recognising that is the point.
    _DROP_DIRS = ("./", "/tmp/", "/var/tmp/", "/dev/shm/")  # nosec B108
    runs_local_path = any(w[0].startswith(_DROP_DIRS) for w in facts.commands if w)
    if fetches and (makes_executable or runs_local_path or binaries & _INTERPRETERS):
        found["download_exec_chain"] = Severity.HIGH

    for words in facts.commands:
        if not words or _basename(words[0]) not in _INTERPRETERS:
            continue
        for i, arg in enumerate(words[1:], start=1):
            if arg.lower() not in _INLINE_CODE_FLAGS:
                continue
            payload = words[i + 1] if i + 1 < len(words) else ""
            severity = (
                Severity.HIGH if _PAYLOAD_EXEC_TOKENS.search(payload) else Severity.MEDIUM
            )
            prior = found.get("interpreter_inline_code")
            if prior is None or severity > prior:
                found["interpreter_inline_code"] = severity
            break

    if fetches and "download_exec_chain" not in found:
        found["network_fetch"] = Severity.MEDIUM

    if any(_DESTRUCTIVE.match(b) for b in binaries):
        found["destructive_command"] = Severity.MEDIUM

    return found


# ── Candidate extraction ──────────────────────────────────────────────────

def _candidates(text: str) -> list[str]:
    """Lines worth parsing as shell, stripped of markdown scaffolding.

    Line-scoped on purpose: it bounds parser cost, and a shell statement is a
    line. Splitting also means one unparseable line cannot hide the next one.
    """
    out: list[str] = []
    for raw in text.splitlines():
        if len(raw) > _MAX_LINE_CHARS or _FENCE_RE.match(raw):
            continue
        line = _PROMPT_RE.sub("", raw).replace("`", " ").strip()
        if not line or not _TRIGGER.search(line):
            continue
        out.append(line)
        # The line itself may be a tool call wrapping the real command.
        for pattern in (_CALL_ARG_RE, _CMD_KEY_RE):
            for m in pattern.finditer(line):
                inner = m.group("cmd").strip()
                if inner and inner != line and _TRIGGER.search(inner):
                    out.append(inner)
        if len(out) >= _MAX_CANDIDATES:
            break
    return out[:_MAX_CANDIDATES]


class CommandInjectionScanner:
    """Shell command-injection scanner. Satisfies the Scanner Protocol."""

    name = "command_injection_scan"
    # Its own family: collapsing it into structural_heuristic would make this
    # scanner and the heuristic one count as a single method in TurnSignals
    # corroboration, when agreeing by two different techniques is the point.
    method_family = "structural_command"

    def __init__(self) -> None:
        if bashlex is None:
            raise ConfigError(
                "command_injection_scan requires the 'shell' extra: "
                "pip install 'shai-harness[shell]'",
                op="build_scanner",
            )

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        if not text or not text.strip():
            return ScanResult()

        worst: dict[str, Severity] = {}
        for candidate in _candidates(text):
            try:
                trees = bashlex.parse(candidate)
            except Exception:
                # Not shell, or shell this parser cannot read. Either way there
                # is nothing to reason about structurally — the catalog and
                # heuristic scanners still see the same text at this boundary.
                continue

            facts = _Facts()
            for tree in trees:
                _walk(tree, facts)

            demote = not (facts.commands and _is_invocation(facts.commands[0][0]))
            for shape, severity in _shapes(facts).items():
                if demote:
                    severity = _DEMOTE.get(severity, Severity.LOW)
                prior = worst.get(shape)
                if prior is None or severity > prior:
                    worst[shape] = severity

        if not worst:
            return ScanResult()

        log.debug(
            "command injection shapes detected",
            extra={"shapes": sorted(worst), **ctx.to_log_fields()},
        )
        return ScanResult(findings=[
            Finding(
                scanner=self.name,
                category=f"command_injection.{shape}",
                severity=severity,
                detail=f"shell composition: {shape}",
            )
            for shape, severity in sorted(worst.items())
        ])
