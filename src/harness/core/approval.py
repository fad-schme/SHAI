"""Approval grant — a signed, bound assertion that a human authorised one call.

Replaces the self-asserted `AgentContext.human_approved` flag. That flag was a
bool on a caller-constructible context: any caller set it by assignment, one
`True` covered every tool and every argument for a whole turn, and the allow
path recorded no approver, no scope, and no expiry. A grant is verifiable,
bound, and recorded.

A grant asserts:
  - approver {approver_id}
  - authorised agent {agent_id} in tenant {tenant_id}
  - to call tool {tool_name}
  - with exactly these arguments ({args_digest})
  - before {expires_at}

**SHAI verifies grants; it does not speak an authorization protocol.** The gate
checks a signature and a binding, offline, with no I/O — it cannot suspend a
run, poll an authorization server, or take a callback, because it does not own
the agent loop. Where the grant came from (a CIBA flow, Auth0, WorkOS, a Slack
button, a terminal prompt) is the integrator's choice, and reminder/escalation/
timeout choreography is the calling application's job.

Quorum is a count of *distinct* approver_ids across the grants presented, so
N-of-M approval is N grants from N approvers. One grant carries one approver,
always — a grant claiming two approvers would be one signature asserting two
independent decisions.

Format and signing mirror `connectivity/token.py`: base64url JSON, HMAC-SHA256
over the canonical encoding of every field except the signature.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from harness.core.signing import claims_of, decode, encode, sign


class ApprovalError(Exception):
    """Raised when a grant is malformed, unverifiable, expired, or unbound."""


@dataclass(frozen=True)
class ApprovalGrant:
    """One approver's signed authorisation for one tool call."""
    version:     int          # always 1 — allows future format migration
    grant_id:    str          # UUID v4
    agent_id:    str
    tenant_id:   str
    tool_name:   str
    args_digest: str          # sha256 over the canonical arguments
    approver_id: str          # who approved — recorded on the gate's audit event
    issued_at:   datetime
    expires_at:  datetime
    signature:   str          # HMAC-SHA256 hex digest


@dataclass(frozen=True)
class ApprovalPolicy:
    """Resolved approval configuration the gate runs with.

    secret=None means approvals are not configured. SENSITIVE and IRREVERSIBLE
    tools are then denied outright rather than falling back to a weaker check —
    an unverifiable approval is what this module exists to remove.
    """
    secret:              bytes | None = None
    sensitive_quorum:    int = 1
    irreversible_quorum: int = 2


# Envelope mechanics — canonical encoding, HMAC, base64url, expiry — live in
# harness.core.signing and are shared with the dispatch token. Only the field
# set, the binding rules, and the error type are this module's.
_SIGNED_FIELDS: tuple[str, ...] = (
    "version", "grant_id", "agent_id", "tenant_id",
    "tool_name", "args_digest", "approver_id", "issued_at", "expires_at",
)


def args_digest(args: dict[str, Any]) -> str:
    """Digest the arguments a grant authorises.

    Binding to the arguments is what makes a grant an approval of *this* call
    rather than a licence: approving a refund of $5 must not authorise a refund
    of $50000. Callers issuing a grant must digest the same arguments they will
    pass to check_tool_call.

    `default=str` mirrors audit canonicalisation — an argument that is not JSON
    native still produces a stable digest instead of failing the approval.
    """
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def sign_grant(
    *,
    agent_id:    str,
    tenant_id:   str,
    tool_name:   str,
    args:        dict[str, Any],
    approver_id: str,
    secret:      bytes,
    ttl_seconds: int = 300,
) -> ApprovalGrant:
    """Issue a signed grant for one approver over one call's arguments.

    ttl_seconds defaults to 5 minutes: long enough for a human to act on an
    out-of-band prompt, short enough that a captured grant is not a standing
    permission. Applications running slower approval flows raise it knowingly.
    """
    if not approver_id.strip():
        raise ApprovalError("approver_id is required — a grant with no approver approves nothing")

    now = datetime.now(UTC)
    grant = ApprovalGrant(
        version=1,
        grant_id=str(uuid.uuid4()),
        agent_id=agent_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        args_digest=args_digest(args),
        approver_id=approver_id,
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        signature="",
    )
    return dataclasses.replace(
        grant, signature=sign(claims_of(grant, _SIGNED_FIELDS), secret)
    )


def encode_grant(grant: ApprovalGrant) -> str:
    """Encode a grant for transport on AgentContext.approvals."""
    return encode(claims_of(grant, _SIGNED_FIELDS), grant.signature)


def verify_grant(encoded: str, secret: bytes) -> ApprovalGrant:
    """Decode and verify one grant's signature and expiry.

    Does not check binding — that is verify_grants(), which knows the call.
    """
    data = decode(
        encoded,
        secret=secret,
        fields=_SIGNED_FIELDS,
        error=ApprovalError,
        noun="grant",
    )
    return ApprovalGrant(
        version=data["version"],
        grant_id=data["grant_id"],
        agent_id=data["agent_id"],
        tenant_id=data["tenant_id"],
        tool_name=data["tool_name"],
        args_digest=data["args_digest"],
        approver_id=data["approver_id"],
        issued_at=data["issued_at"],
        expires_at=data["expires_at"],
        signature=data["signature"],
    )


def verify_grants(
    encoded: tuple[str, ...],
    *,
    secret:    bytes,
    agent_id:  str,
    tenant_id: str,
    tool_name: str,
    args:      dict[str, Any],
    quorum:    int,
) -> list[str]:
    """Verify every grant, enforce binding, and return the distinct approvers.

    Raises ApprovalError naming the first failure. A grant that verifies but is
    bound to another agent, tenant, tool, or argument set is rejected here — the
    signature proves who issued it, the binding proves what it authorises, and
    neither is sufficient alone.
    """
    digest = args_digest(args)
    approvers: list[str] = []

    for item in encoded:
        grant = verify_grant(item, secret)
        if grant.agent_id != agent_id:
            raise ApprovalError(f"grant {grant.grant_id} is bound to a different agent")
        if grant.tenant_id != tenant_id:
            raise ApprovalError(f"grant {grant.grant_id} is bound to a different tenant")
        if grant.tool_name != tool_name:
            raise ApprovalError(f"grant {grant.grant_id} is bound to a different tool")
        if not hmac.compare_digest(grant.args_digest, digest):
            raise ApprovalError(f"grant {grant.grant_id} is bound to different arguments")
        if grant.approver_id not in approvers:
            approvers.append(grant.approver_id)

    if len(approvers) < quorum:
        raise ApprovalError(
            f"{len(approvers)} distinct approver(s) presented, {quorum} required"
        )
    return approvers
