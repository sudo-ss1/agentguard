"""Cedar policy decisions for tool calls.

Each tool call becomes a Cedar request: principal Agent::"<id>", action Action::"<tool>",
resource Tool::"<tool>", plus a context built from the arguments (normalized path, URL host,
recipient domain). Tools missing from the schema get NoDecision, which the gateway denies.
"""

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import cedarpy

from agentguard import labfs
from agentguard.gateway.checks import CallContext, Decision

PATH_TOOLS = {"read_file", "write_file", "list_dir", "delete_file"}
_POLICY_START = re.compile(r'(?:@id\("([^"]+)"\)\s*)?\b(?:permit|forbid)\s*\(')
_LINE_COMMENT = re.compile(r"//[^\n]*")


def build_context(tool: str, arguments: dict[str, Any], input_schema: dict[str, Any]) -> dict:
    """Turn raw tool arguments into the attributes policies are written against."""
    defaults = {
        k: v["default"]
        for k, v in input_schema.get("properties", {}).items()
        if isinstance(v, dict) and "default" in v
    }
    args = {**defaults, **arguments}

    def text(name: str) -> str:
        value = args.get(name)
        if not isinstance(value, str):
            raise ValueError(f"argument {name!r} must be a string")
        return value

    if tool in PATH_TOOLS:
        return {"path": labfs.normalize(text("path"))}
    if tool == "fetch_url":
        url = urlsplit(text("url"))
        return {"url_scheme": url.scheme.lower(), "url_host": (url.hostname or "").lower()}
    if tool == "send_email":
        recipient = text("to").strip().lower()
        return {"recipient": recipient, "recipient_domain": recipient.rpartition("@")[2]}
    return {}


class CedarCheck:
    name = "cedar"

    def __init__(self, policy_dir: Path) -> None:
        text = "\n".join(p.read_text() for p in sorted(policy_dir.glob("*.cedar")))
        schema_text = (policy_dir / "schema.cedarschema").read_text()
        result = cedarpy.validate_policies(text, schema_text)
        if not result.validation_passed:
            raise ValueError(f"Cedar policies fail schema validation: {result.errors}")
        self.policies = cedarpy.PolicySet.from_str(text)
        self.schema = cedarpy.Schema.from_str(schema_text)
        # cedarpy names policies policy0, policy1... in source order; map back to @id.
        uncommented = _LINE_COMMENT.sub("", text)
        self.ids = [
            m.group(1) or f"policy{i}" for i, m in enumerate(_POLICY_START.finditer(uncommented))
        ]

    def evaluate(self, ctx: CallContext) -> Decision:
        if ctx.agent_id is None:
            return Decision("deny", "no agent identity", "unidentified-agent")
        request = {
            "principal": {"type": "Agent", "id": ctx.agent_id},
            "action": {"type": "Action", "id": ctx.tool},
            "resource": {"type": "Tool", "id": ctx.tool},
            "context": build_context(ctx.tool, ctx.arguments, ctx.input_schema),
        }
        result = cedarpy.is_authorized(request, self.policies, [], schema=self.schema)
        matched = [self._id(r) for r in result.diagnostics.reasons]
        if result.allowed:
            return Decision("allow", "permitted", ",".join(matched))
        if matched:  # a forbid matched
            return Decision(
                "deny", f"forbidden by policy for context {request['context']}", ",".join(matched)
            )
        errors = "; ".join(result.diagnostics.errors)
        return Decision(
            "deny", errors or f"no policy permits context {request['context']}", "default-deny"
        )

    def _id(self, cedar_name: str) -> str:
        index = int(cedar_name.removeprefix("policy"))
        return self.ids[index] if index < len(self.ids) else cedar_name
