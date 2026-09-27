from agentguard.gateway.checks import AllowlistCheck, CallContext, Decision, run_pipeline


class Boom:
    name = "boom"

    def evaluate(self, ctx):
        raise RuntimeError("policy store unreachable")


class Allow:
    name = "allow"

    def evaluate(self, ctx):
        return Decision("allow", "ok", "allow")


CTX = CallContext("research-bot", "read_file", "files", {"path": "notes.txt"})


def test_exception_fails_closed():
    decision = run_pipeline([Allow(), Boom()], CTX)
    assert not decision.allowed and decision.policy_id == "boom-error"


def test_first_deny_wins_and_later_checks_do_not_run():
    allowlist = AllowlistCheck({"research-bot": {"list_dir"}})
    decision = run_pipeline([allowlist, Boom()], CTX)
    assert decision.policy_id == "allowlist" and not decision.allowed


def test_empty_pipeline_denies():
    assert not run_pipeline([], CTX).allowed
