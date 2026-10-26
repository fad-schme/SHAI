"""control_vocabulary.py — the one definition of the injection-control vocabulary.

The heuristic scanner counts these tokens and markers when it scores text, and the
candidate fingerprint extracts them as the evidence of the candidate that scoring
produced. Both import this module, so the two cannot drift apart again.
"""
from __future__ import annotations

import re

CONTROL_TOKENS = frozenset({
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

STRUCTURAL_RE = re.compile(
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
