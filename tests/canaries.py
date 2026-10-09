"""Canary secrets for scanner tests: made at test time, so nothing key-shaped is committed."""

import secrets
import string

from agentguard.attacks import api_key_canary

ALNUM = string.ascii_letters + string.digits


def anthropic_canary() -> str:
    """Shaped like an Anthropic API key (gitleaks `anthropic-api-key`), marked as a canary."""
    return api_key_canary()


def github_canary() -> str:
    return "ghp_" + "".join(secrets.choice(ALNUM) for _ in range(36))


def pieces(secret: str, n: int = 8) -> set[str]:
    return {secret[i : i + n] for i in range(len(secret) - n + 1)}


def assert_absent(canaries: list[str], *outputs: str) -> None:
    """No 8-character piece of any canary appears in any output."""
    for canary in canaries:
        for output in outputs:
            leaked = [p for p in pieces(canary) if p in output]
            assert not leaked, f"{len(leaked)} piece(s) of a canary appear in the output"
