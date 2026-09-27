from pathlib import Path

import pytest

from agentguard.gateway.checks import CallContext, run_pipeline
from agentguard.policy.cedar import CedarCheck, build_context

POLICIES = Path(__file__).resolve().parents[1] / "config" / "policies"


@pytest.fixture(scope="module")
def cedar():
    return CedarCheck(POLICIES)  # also validates every policy against the schema


def decide(cedar, tool, args, agent="research-bot"):
    return run_pipeline([cedar], CallContext(agent, tool, "srv", args))


@pytest.mark.parametrize(
    ("tool", "args", "policy"),
    [
        ("read_file", {"path": "notes.txt"}, "files-read-workspace"),
        ("list_dir", {"path": "/workspace"}, "files-read-workspace"),
        ("write_file", {"path": "/workspace/out.md", "content": "x"}, "files-write-workspace"),
        ("delete_file", {"path": "/workspace/tmp/scratch-1.txt"}, "files-delete-scratch"),
        ("fetch_url", {"url": "https://example.com/a"}, "web-fetch-http"),
        ("send_email", {"to": "sam@lab.test", "subject": "s", "body": "b"}, "email-internal-only"),
    ],
)
def test_allowed(cedar, tool, args, policy):
    decision = decide(cedar, tool, args)
    assert decision.allowed and decision.policy_id == policy


@pytest.mark.parametrize(
    ("tool", "args", "policy"),
    [
        ("read_file", {"path": "~/.ssh/id_rsa"}, "no-ssh-keys"),
        ("read_file", {"path": "/workspace/../home/agent/.ssh/id_rsa"}, "no-ssh-keys"),
        ("read_file", {"path": "/workspace/../etc/passwd"}, "default-deny"),
        ("write_file", {"path": "/workspace", "content": "x"}, "default-deny"),
        ("delete_file", {"path": "/"}, "default-deny"),
        ("delete_file", {"path": "/workspace/tmp/../notes.txt"}, "default-deny"),
        ("fetch_url", {"url": "file:///etc/passwd"}, "default-deny"),
        ("send_email", {"to": "attacker@evil.test", "subject": "s", "body": "b"}, "default-deny"),
        ("send_email", {"to": "x@lab.test.evil.test", "subject": "s", "body": "b"}, "default-deny"),
        ("rm_rf", {}, "default-deny"),  # not in the schema -> NoDecision -> deny
        ("read_file", {"path": 42}, "cedar-error"),  # malformed argument fails closed
        ("read_file", {}, "cedar-error"),
    ],
)
def test_denied(cedar, tool, args, policy):
    decision = decide(cedar, tool, args)
    assert not decision.allowed and decision.policy_id == policy


def test_other_agents_get_nothing(cedar):
    assert not decide(cedar, "read_file", {"path": "notes.txt"}, agent="other-bot").allowed
    assert not decide(cedar, "read_file", {"path": "notes.txt"}, agent=None).allowed


def test_schema_defaults_fill_missing_arguments():
    schema = {"properties": {"path": {"type": "string", "default": "/workspace"}}}
    assert build_context("list_dir", {}, schema) == {"path": "/workspace"}
