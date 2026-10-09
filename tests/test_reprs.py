"""No class that holds raw tool arguments, tool results or secret values shows them in its repr.

A repr ends up in log lines, tracebacks and failed-assertion output. Each class below is built
with canaries in its sensitive fields; neither repr() nor str() may show any piece of them.
Classes with generated reprs only: a plain class's default repr shows no field values.
"""

from pathlib import Path

from agentguard.agent.scripted import Acting, Step
from agentguard.agent.toolbox import ToolResult
from agentguard.attacks import Outcome, Scenario
from agentguard.discovery.files import TextFile
from agentguard.discovery.history import HistoryBlob
from agentguard.gateway.checks import CallContext, Decision
from agentguard.gateway.identity import Identity
from agentguard.guards import GuardResult
from agentguard.guards.result_scan import ScanResult, Stripped
from agentguard.guards.secrets import SecretFinding, TextFinding
from agentguard.identity.client import Credentials
from agentguard.identity.didkey import AgentKey
from agentguard.identity.service import RegisterRequest, Registration
from agentguard.identity.vc import AgentProfile
from agentguard.lab_stack import Lab
from agentguard.runlog import TrialRecord
from tests.canaries import anthropic_canary, assert_absent, github_canary


def test_no_repr_shows_arguments_results_or_secrets():
    arg, result, token = anthropic_canary(), github_canary(), github_canary()
    key = AgentKey.generate()
    private = bytes(key.signing_key).hex()
    profile = AgentProfile("bot", key.did, "lab-owner", "test", ("read_file",), "m")
    credentials = Credentials("bot", key, "vc", token)
    step = Step(tool="send_email", args={"body": arg}, acting=Acting(agent="bot", token=token))
    objects = {
        "CallContext": CallContext(
            "bot", "send_email", "email", {"body": arg}, identity=Identity(profile, token)
        ),
        "Identity": Identity(profile, token),
        "Decision": Decision("deny", "secret in arguments", "secret-scan", {"secret": arg}),
        "GuardResult": GuardResult("deny", "secret in arguments", "secret-scan", {"secret": arg}),
        "SecretFinding": SecretFinding("anthropic-api-key", "body", arg),
        "TextFinding": TextFinding("anthropic-api-key", arg, 0),
        "Credentials": credentials,
        "Registration": Registration(profile, "vc", token),
        "RegisterRequest": RegisterRequest(registration=token),
        "Acting": Acting(agent="bot", token=token),
        "Step": step,
        "Scenario": Scenario(
            id=0, name="n", owasp="o", available_from_phase=1, blocked_in_phase=1, scripted=[step]
        ),
        "ToolResult": ToolResult(result, False),
        "Outcome": Outcome(False, "blocked", calls=[("send_email", {"body": arg})]),
        "TrialRecord": TrialRecord(
            1, "guarded", 1, False, "blocked", (0, 1), refusals=[{"target": arg}]
        ),
        "Stripped": Stripped(result, [("css-hidden", arg)]),
        "ScanResult": ScanResult(stripped_content=arg),
        "TextFile": TextFile(Path("a.env"), "a.env", arg, 0.0, 0),
        "HistoryBlob": HistoryBlob("c0ffee", "a.env", arg, 0),
        "Lab": Lab(
            {},
            "http://evil.test",
            Path("."),
            Path("o"),
            Path("r"),
            credentials={"bot": credentials},
        ),
    }
    for name, obj in objects.items():
        try:
            assert_absent([arg, result, token, private], repr(obj), str(obj))
        except AssertionError as exc:
            raise AssertionError(f"{name}: {exc}") from None
