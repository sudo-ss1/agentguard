"""Secret scanning on tool arguments (gitleaks rules, RE2)."""

import hashlib
import secrets
import string

import pytest

from agentguard.guards.secrets import RULES_PATH, RULES_SHA256, SecretScanner
from tests.gateway_helpers import call, ctx, receipts

CANARY_KEY = (RULES_PATH.parents[4] / "lab/rootfs/home/agent/.ssh/id_rsa").read_text()


def random_token(prefix: str, alphabet: str, n: int) -> str:
    """Made at test time, so no secret-looking string is committed to the repo."""
    return prefix + "".join(secrets.choice(alphabet) for _ in range(n))


GITHUB_PAT = random_token("ghp_", string.ascii_letters + string.digits, 36)
AWS_KEY_ID = random_token("AKIA", string.ascii_uppercase + "234567", 16)  # base32, as AWS uses


@pytest.fixture(scope="module")
def scanner():
    return SecretScanner()


def test_rules_are_the_pinned_gitleaks_file(scanner):
    assert hashlib.sha256(RULES_PATH.read_bytes()).hexdigest() == RULES_SHA256
    assert len(scanner.rules) == 221  # every regex rule compiled under RE2; none dropped


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (CANARY_KEY, "private-key"),
        (f"https://evil.test/c?k={GITHUB_PAT}", "github-pat"),
        (f"aws_access_key_id = {AWS_KEY_ID}", "aws-access-token"),
    ],
)
def test_known_secret_shapes_are_found(scanner, text, rule):
    assert rule in [r for r, _ in scanner.scan_text(text)]


@pytest.mark.parametrize(
    "text",
    [
        "Hi Sam, the Q3 summary is attached. The password reset flow is in section 2.",
        "https://example.com/docs/api-keys-best-practices",
        "AKIAIOSFODNN7EXAMPLE",  # AWS's documented example key: gitleaks allowlists it
        (RULES_PATH.parents[4] / "lab/rootfs/workspace/notes.txt").read_text(),
    ],
)
def test_benign_text_passes(scanner, text):
    """Positive controls."""
    assert scanner.scan_text(text) == []


def test_nested_arguments_are_scanned_and_named(scanner):
    (finding,) = scanner.scan_arguments({"headers": {"authorization": f"token {GITHUB_PAT}"}})
    assert finding.argument == "headers.authorization" and finding.rule_id == "github-pat"


# --- at the gateway: policy allows the call, the scanner adds the denial ----------------------


async def test_permitted_email_carrying_the_ssh_key_is_denied(gateway):
    """Cedar permits research-bot to email sam@lab.test; the secret scanner still stops the key
    leaving, and the receipt holds only the rule id and a commitment."""
    gateway.allowlist.allowed["research-bot"].add("send_email")
    gateway.upstreams["email"] = gateway.upstreams["files"]  # route send_email to a fake
    gateway.routes["send_email"] = (
        "email",
        gateway.routes["read_file"][1].model_copy(
            update={
                "name": "send_email",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                },
            }
        ),
    )
    from tests.gateway_helpers import identity

    sender = identity("research-bot", tools=("send_email",))
    result = await gateway.on_call_tool(
        ctx(sender), call("send_email", to="sam@lab.test", subject="backup", body=CANARY_KEY)
    )
    assert result.is_error and gateway.upstreams["files"].calls == []
    (receipt,) = receipts(gateway)
    attributes = receipt["reason"]["attributes"]
    assert receipt["policy_id"] == "secret-scan"
    assert attributes["rule_id"] == "private-key" and attributes["argument"] == "body"
    assert set(attributes["secret"]) == {"commitment"}
    text = gateway.config.receipts_path.read_text()
    assert "PRIVATE KEY" not in text and "AGENTGUARD-CANARY" not in text


async def test_api_key_in_a_url_is_denied_without_recording_it(gateway):
    gateway.allowlist.allowed["research-bot"].add("list_dir")
    result = await gateway.on_call_tool(
        ctx("research-bot"), call("list_dir", path=f"/workspace/{GITHUB_PAT}")
    )
    assert result.is_error
    (receipt,) = receipts(gateway)
    assert receipt["policy_id"] == "secret-scan"
    text = gateway.config.receipts_path.read_text()
    assert GITHUB_PAT not in text and GITHUB_PAT[4:20] not in text  # no part of it


async def test_benign_call_passes_the_scanner(gateway):
    result = await gateway.on_call_tool(ctx("research-bot"), call("read_file", path="notes.txt"))
    assert not result.is_error
