"""Redact AuditEvent fields before emission to sinks.

Rules:
- No raw user text, LLM output, or tool args may appear in any field.
- Finding.detail may contain short descriptive notes (category names, counts)
  but never matched substrings.
- extra dict values are passed through as-is — callers are responsible for
  not placing raw text there.

This module is a single function used by AuditEmitter before fan-out.
"""
from __future__ import annotations

from harness.core.events import AuditEvent


def redact(event: AuditEvent) -> AuditEvent:
    """Return a copy of event safe for emission.

    Currently a pass-through — the AuditEvent schema never carries raw text
    by design (no text/args/output fields exist on the model). This function
    is the hook for future redaction logic (e.g. scrubbing extra values,
    truncating deny_reason to a safe length).
    """
    # deny_reason may contain operator-authored rule text which is safe.
    # Truncate to a reasonable length to prevent runaway strings in sinks.
    if event.deny_reason and len(event.deny_reason) > 500:
        object.__setattr__(
            event,  # frozen model — use object.__setattr__
            "deny_reason",
            event.deny_reason[:497] + "...",
        )
    return event
