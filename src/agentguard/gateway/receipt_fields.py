"""What a receipt may show of a call: the coarse attributes kept in the clear, the path class,
and the argument hash. Pure helpers with no ledger dependency, so read-only views (the
dashboard) can redact the same way receipts do without importing the ledger writer."""

import hashlib
import json
from typing import Any

from agentguard.ledger.canonical import CanonicalError, jcs

# Attribute values that are coarse enough to keep in the clear.
CLEAR_ATTRIBUTES = frozenset(
    {
        "recipient_domain",
        "url_host",
        "url_scheme",
        "path_class",
        # guard metadata, not argument values
        "limit",
        "window_s",
        "kill_switch",
        "kill_category",  # a fixed category (manual, budget, unknown); the reason is committed
        "rule_id",  # a scanner rule's id, never the matched value
        "argument",  # which argument a finding was in, e.g. "body"
    }
)


def args_digest(arguments: dict[str, Any]) -> str:
    """The receipt's argument hash: SHA-256 of the arguments in RFC 8785 canonical JSON, so it
    is reproducible anywhere. Receipts never store argument values themselves.

    Raises CanonicalError for arguments RFC 8785 can't represent exactly (e.g. integers beyond
    2**53). The gateway denies such calls (`arguments-not-canonical`) and records them with the
    legacy hash, marked `args_hash: legacy-json`."""
    return hashlib.sha256(jcs(arguments)).hexdigest()


def legacy_args_digest(arguments: dict[str, Any]) -> str:
    """The argument hash used before Phase 5 (sorted-key json.dumps). Kept for reading run logs
    recorded before 2026-10-01; new receipts never use it."""
    canonical = json.dumps(arguments, sort_keys=True, default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


def args_match(arguments: dict[str, Any], digest: str) -> bool:
    """Whether `digest` is the argument hash of `arguments`, in either format."""
    try:
        if args_digest(arguments) == digest:
            return True
    except CanonicalError:
        pass
    return legacy_args_digest(arguments) == digest


def path_class(path: str) -> str:
    if path == "/workspace/tmp" or path.startswith("/workspace/tmp/"):
        return "inside /workspace/tmp"
    if path == "/workspace" or path.startswith("/workspace/"):
        return "inside /workspace"
    return "outside /workspace"
