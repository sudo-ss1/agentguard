# Architecture

## Target (all phases)

Every tool call passes through the gateway, which checks who the agent is, whether this exact
action is allowed, and writes a signed receipt. Nothing reaches a tool without a decision.

```mermaid
sequenceDiagram
    participant A as Agent (LangGraph)
    participant G as AgentGuard Gateway
    participant P as Policy Engine (Cedar)
    participant H as Human approver
    participant T as MCP Tool Server
    participant L as Audit Ledger
    A->>G: tool call + capability token
    G->>G: verify signature, token caveats
    G->>G: scan args for secrets / injection
    G->>P: is this allowed?
    P-->>G: allow / deny / needs approval
    G->>H: approve high-risk action?
    H-->>G: yes
    G->>T: forward call (scoped token)
    T-->>G: result
    G->>G: scan result for injection
    G->>L: signed receipt (hash-chained)
    G-->>A: result
```

## Phase 1: vulnerable baseline

```mermaid
flowchart LR
    A[Agent<br/>LangGraph + Ollama] -- MCP streamable HTTP --> F[files server]
    A -- MCP --> W[web server]
    A -- MCP --> E[email stub]
    W -- HTTP --> X[evil.test<br/>nginx]
    F -.-> R[(lab rootfs<br/>incl. canary SSH key)]
    E -.-> O[(outbox.jsonl)]
```

- The agent reaches tools only through the URLs in `config/agent.baseline.yaml`. Phase 2 puts
  the gateway in front by switching to `config/agent.guarded.yaml`, which lists only the gateway.
- `agentguard.agent.toolbox.Toolbox` is the only MCP client. It serves both the LLM graph and
  the scripted driver, and records every call for the attack oracles.
- Tool servers run on an internal Docker network with no internet access. The files server
  maps `/` and `~` into the lab rootfs (`agentguard.labfs`). That is lab containment, not
  a security control: inside the lab the server is deliberately unrestricted.

## Phase 2: gateway and policy

```mermaid
flowchart LR
    A[Agent] -- "MCP + X-Agent-Id" --> G
    subgraph G[AgentGuard gateway]
        direction TB
        Q[pins / quarantine] --> AL[tool allowlist] --> AR[declared arguments] --> C[Cedar]
    end
    G -- only if allowed --> F[files] & W[web] & E[email] & WX[weather]
    G -.-> RC[(receipts.jsonl)]
    G -. background refresh .-> WX
```

`src/agentguard/gateway/proxy.py` is an MCP server (low-level `mcp.server.lowlevel.Server`, so
upstream schemas pass through unchanged) that is also an MCP client of every upstream.

**tools/call** runs the checks in order. The first one that doesn't allow the call ends it, and
any exception is a deny (`run_pipeline` in `gateway/checks.py`):

| Check | Denies when | Policy id in receipts |
| --- | --- | --- |
| `PinStore` | the tool's server is quarantined | `pin-quarantine` |
| `AllowlistCheck` | the tool isn't on the agent's list in `gateway.yaml`, or there's no agent id | `allowlist` |
| `ArgumentSchemaCheck` | an argument isn't declared in the pinned input schema | `undeclared-arguments` |
| `CedarCheck` | no Cedar policy permits it, a `forbid` matches, or the tool isn't in the schema | `@id` of the forbid, or `default-deny` |

Every decision, allow or deny, is written to `receipts.jsonl` with the agent, tool, argument
hash, policy id and decision time. Phase 5 turns this into the signed, hash-chained ledger.

**Cedar requests.** Principal `Agent::"<id>"`, action and resource `Action`/`Tool::"<tool>"`,
and a context built from the arguments by `build_context` in `policy/cedar.py`:

- File tools get `path`, normalized exactly as the files server will resolve it
  (`labfs.normalize`). So `/workspace/../home/agent/.ssh/id_rsa` is judged as the SSH key.
- `fetch_url` gets `url_scheme` and `url_host`.
- `send_email` gets `recipient` and `recipient_domain`.

Policies live in `config/policies/*.cedar` and are validated against
`schema.cedarschema` when the gateway starts. A tool missing from the schema gets `NoDecision`,
which is a deny.

**tools/list** returns the gateway's own verified copies of tool definitions, filtered by the
agent's allowlist and with quarantined servers removed. A changed upstream description
therefore never reaches the agent. A background loop (`refresh_interval_s`) re-fetches upstream
lists, pins new tools (trust on first use), and quarantines a server whose pinned tool changed.
Pins and quarantines persist in `pins.json`. To re-approve a server, stop the gateway and edit
that file. In Docker the file lives in the `lab-state` volume, so `docker compose down -v`
resets it.

Two details worth knowing:

- **The list handler must be cheap.** mcp 2's HTTP transport calls the server's own
  `tools/list` before every `tools/call`, to validate `Mcp-Param-*` headers. An early version
  refreshed upstreams inside the handler and added ~10 ms to every call.
- **Tool shadowing.** If two upstreams offer the same tool name, the first in `upstreams`
  wins and the other is logged and ignored.

**Identity** is the `X-Agent-Id` header in this phase, which is trivially forgeable. Phase 3
replaces it with DID-bound Biscuit tokens.

### Known gaps, tracked for later phases

- Nothing limits how often a tool is called (attack 6). Budgets and the kill switch come in
  Phase 4.
- `fetch_url` may reach any http(s) host, and results are not scanned. The egress allowlist
  and injection scanner come in Phase 4.
- A rug pull is detected only after the next refresh. Until then, calls to that server are
  still judged by the other checks.

### Open finding: receipts expose cleartext policy context (to settle in Phase 3)

Receipts store only a hash of each call's arguments (`args_digest`). The `reason` string on a
**denial**, however, quotes the Cedar policy context in cleartext, so receipts are not hash-only.
Confirmed from a real gateway run of attack 1 (2026-09-27):

```
deny read_file  | forbidden by policy for context {'path': '/home/agent/.ssh/id_rsa'}
deny send_email | no policy permits context {'recipient': 'attacker@evil.test', 'recipient_domain': 'evil.test'}
```

What each field can expose:

| Source | Exposes | Does not expose |
| --- | --- | --- |
| Cedar denials (`policy/cedar.py`) | normalized `path`; full email `recipient` and `recipient_domain`; `url_scheme` and `url_host` | email subject or body, file contents, URL path or query |
| Pipeline errors (`checks.run_pipeline`) | the exception text; today's messages name arguments but hold no values | — |
| `upstream_error` on forwarded calls (`proxy.py`) | `repr(exc)` of the upstream failure, which can contain anything the library put there | — |
| Allowlist and undeclared-argument denials | tool and argument *names* only | values |

A full recipient address in a verifiable audit log is a worse exposure than a file path.

**Why this must be settled in Phase 3.** Phase 5 hash-chains every receipt, including `reason`,
into the signed audit ledger. After that, a reason can't be redacted without breaking the chain.
So the reason format must be decided before the ledger commits to it. The options and a
recommendation are in the Phase 3 design proposal. **Behaviour is unchanged for now.**
