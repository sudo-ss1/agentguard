# Phase 6 design: visibility

Approved 2026-10-09. Targets attack 8 ("API key committed in a repo"). Adds a discovery
scanner, an explainable risk score per agent, a minimal dashboard, and ledger receipts for
kill-switch changes.

## Guiding rules

- **Visibility never grants anything.** The scanner, the risk score and the dashboard are
  read-only views. A score allows no call and changes no policy; nothing here sits in the
  gateway's decision path.
- **No secret leaves the place it was found.** A credential is reported as its rule id, file,
  line and a keyed fingerprint. The matched text, the line it is on, and any exception message
  are never printed, logged or stored.
- **Local and read-only.** The scanner opens files read-only, writes only the `--out` file, and
  makes no network calls. It never runs code from a scanned repo.
- **Unknown means worst case.** An input the scanner or risk engine can't determine scores as 1
  and is labelled `unknown`, so unregistered agents tend to rank high. That is intended.

## Decisions

| Area | Decision |
| --- | --- |
| Scanner | `agentguard scan`: MCP client configs, LLM SDK imports, model names, and credentials found by the vendored gitleaks rules (the Phase 4 `SecretScanner`, v8.30.1, SHA-256 pinned). Outputs a JSON inventory (AI bill of materials). |
| Credential reporting | Fingerprint only: `HMAC-SHA256(scanner key, secret)`, first 16 hex characters. No commitment and no salt store. The key is local (file mode 0600) and never output. `agentguard fingerprint` reads a suspected key on stdin (never argv) and prints its fingerprint, to confirm a finding later. |
| Repo allowlists | A scanned repo's own `.gitleaks.toml` is ignored: an attacker-controlled repo could use it to hide keys. The operator can pass `--allowlist FILE`. gitleaks' global path allowlists (lock files, images…) apply. |
| History | `--history` reads every commit with dulwich's object store, never with the `git` binary (see "Reading history" below). |
| Process and DNS watching | Future work. From WSL2 the Windows-side clients (Claude Desktop, Cursor) are invisible, DNS capture needs root, polling misses short connections, and it observes other people's activity. `last_seen` comes from the ledger and file times instead. |
| Agents | Registered agents (`config/identity.yaml`, `config/gateway.yaml`) and discovered ones (MCP clients, repos with SDK imports), labelled `shadow` when unregistered. `config/inventory.yaml` maps an agent to its source paths; it is kept out of `identity.yaml` because that file's contents go into the credential. |
| Risk weights | Privilege 0.30, data sensitivity 0.20, autonomy 0.20, supply chain 0.15, anomaly 0.15. Judgment calls, good to about one significant figure; configurable; raw factors always output. |
| Dashboard | Streamlit, an optional extra (`uv sync --extra dashboard`), bound to `127.0.0.1`, usage statistics off. Reads the ledger read-only. Actions call the same functions as the CLI. Local lab only; against Docker it is view-only and shows the `docker compose exec gateway …` command. |
| Control receipts | Every change to the kill list (kill, revive, guard reset, budget trip) gets a signed `control` receipt from the gateway, the ledger's only writer. A change made while the gateway was stopped is detected at startup and recorded, never silently accepted. |

## Discovery scanner

```
agentguard scan [PATHS...] [--machine] [--history] [--agents config/inventory.yaml]
                [--receipts receipts.jsonl] [--allowlist FILE] [--key-file PATH] [--out FILE]
agentguard fingerprint [--key-file PATH]      # suspected key on stdin
```

Exit codes: 0 complete with no credentials, 1 credentials found, 3 something wasn't scanned
(and no credentials), 2 bad input. An incomplete scan never exits 0. The key defaults to
`$XDG_STATE_HOME/agentguard/scanner.key`.

`PATHS` are repos or directories. `--machine` adds the known MCP client config locations for
the current user: Linux paths, and in WSL the Windows ones under `/mnt/c/Users/*/AppData`.
Nothing outside `PATHS` is read unless `--machine` is passed. Tests use fixtures only.

### What it finds

- **MCP client configs.** Claude Desktop (`claude_desktop_config.json`), Cursor
  (`.cursor/mcp.json`), VS Code (`mcp.json`, `settings.json` → `mcp`). VS Code files are JSONC:
  comments and trailing commas are stripped before parsing. A file that still won't parse is
  reported `unparsed`, not skipped.
- **What is kept from a server entry**, a fixed set of fields and never raw arguments, since
  arguments and env values often carry tokens:
  - server name, transport, command basename
  - package or image, with its version or digest if any (`npx -y pkg@1.2.3`, `uvx pkg==…`,
    `docker run image@sha256:…`); `pinned: false` when there is none
  - for remote servers, the URL's host only
  - environment variable names, never values
  - `entry_sha256`, a hash of the whole entry, to notice changes between scans
- **LLM SDKs.** Python imports (`anthropic`, `openai`, `google.genai`,
  `google.generativeai`, `langchain_*`, `langgraph`, `ollama`, `litellm`, `mistralai`,
  `cohere`) and `package.json` dependencies (`@anthropic-ai/sdk`, `openai`,
  `@google/genai`, `@modelcontextprotocol/sdk`, …).
- **Models.** Strings shaped like model ids (`claude-*`, `gpt-*`, `gemini-*`, `qwen*`,
  `llama*`, …), tagged `heuristic`.
- **Credentials.** The gitleaks rules over every scanned file, with line numbers.

### Output

```json
{"scanner": {"version": "…", "rules": "gitleaks v8.30.1", "rules_sha256": "e163…",
             "started": "…", "roots": ["…"], "history": false},
 "agents": [{"agent": "research-bot", "kind": "registered", "owner": "lab-owner",
             "models": ["qwen2.5:7b-instruct"], "tools": ["read_file", "…"],
             "mcp_servers": [], "sdks": ["langchain_ollama"],
             "credentials": [{"rule_id": "anthropic-api-key", "file": "app/settings.py",
                              "line": 3, "fingerprint": "3fa2c9…", "commit": null}],
             "last_seen": {"at": "…", "source": "ledger"}, "sources": ["…"]}],
 "not_scanned": [{"path": "…", "reason": "unreadable (PermissionError)"}]}
```

- `owner`: the credential's sponsor for a registered agent, otherwise the OS owner of the
  config or repo.
- `last_seen`: the agent's newest ledger receipt for a registered agent, otherwise the newest
  modification time among its files, labelled by `source`.
- `commit`: the commit id, for findings from `--history`.
- Anything that can't be read or parsed is listed in `not_scanned` with a reason. Errors are
  reported as the exception class only.

### Read-only and local

- Files are opened read-only; the only write is `--out` (and the scanner key on first use).
- Symlinks leading outside a scanned root aren't followed. Files over a size cap (1 MiB) are
  reported in `not_scanned`.
- No network: nothing in the scanner imports an HTTP client, and the tests block sockets.

### Reading history

Running `git` on a repo you don't trust can execute code from that repo's config. Tested on
git 2.43 with a fixture repo (2026-10-09):

| Command | What ran |
| --- | --- |
| `git log -p` | the repo's `diff.<driver>.textconv` (via `.gitattributes`) |
| `git status` | the repo's `core.fsmonitor` |
| `git log -p --no-ext-diff --no-textconv` with `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `-c core.fsmonitor=false -c core.hooksPath=/dev/null` | **the repo's `gpg.program`**, through `log.showSignature=true` and a commit with a `gpgsig` header |

Git has no switch that ignores a repository's own `.git/config`, so hardening by flags is a
denylist: each `-c` override closes one known hole, and an unknown one stays open.

**Decision: dulwich, reading objects directly.**

- The scanner opens `DiskObjectStore` and the refs only. It never constructs a dulwich `Repo`,
  never reads `.git/config`, and never calls `get_blob_normalizer`. In dulwich (1.2.17 read
  as source, 1.2.15 as installed) the modules that start processes are `hooks`, `filters`, `signature`, `merge_drivers`, `patch`,
  `diffstat`, `rebase`, `client` and `cli`. None is imported by `object_store`, `objects`,
  `pack`, `refs`, `diff_tree` or `walk`.
- Diffs are computed by comparing trees: each blob added or changed by a commit is scanned
  whole, and a finding is attributed to the first commit that introduced that blob.
- `objects/info/alternates` would make the store read other repos' objects from anywhere on
  disk. A repo that has one is listed in `not_scanned`.
- Resource limits: the same per-blob size cap, and a cap on commits walked, reported if hit.
  The size cap is applied after a blob is loaded: dulwich has no public way to read an object's
  size without decompressing it, and doing so for packed objects (including delta targets)
  would mean parsing pack internals that change between versions. A hostile repo can
  therefore still cost memory.
- Licence: Apache-2.0 OR GPL-2.0-or-later; used under Apache-2.0. Pinned to 1.2.15, the
  newest release at least two weeks old on 2026-10-09 (1.2.17 was six days old).
- The test is a fixture repo whose config sets every executing hook found above (textconv,
  external diff, fsmonitor, pager, `log.showSignature` with `gpg.program`, a hook). Each would
  create a marker file if it ran. `scan --history` must find the committed canary and no
  marker may exist afterwards.

## Risk score

Risk = 100 × Σ wᵢ·fᵢ, with each factor fᵢ in [0, 1]. The output always carries every factor,
its inputs and the evidence for them (rule ids and locations, policy ids, receipt seqs).

| Factor | Weight | Definition | Source |
| --- | --- | --- | --- |
| Privilege | 0.30 | 0.6 × tool tier + 0.4 × unmediated credentials. Tool tier: the most dangerous allowed tool (credential ∩ gateway allowlist): read ⅓, local write ⅔, external effect or destructive 1. Unmediated credentials: 1 if the scanner found a credential in the agent's sources (ASI03: standing authority that doesn't pass through the gateway). | gateway config, credential, inventory |
| Data sensitivity | 0.20 | Fixed probe requests run through the agent's real Cedar policies (`read_file` of `~/.ssh/id_rsa`, `/etc/passwd`, `/workspace/x`): 1 if any read outside `/workspace` is permitted, 0.3 if only `/workspace`, 0 if no read tool. | policies |
| Autonomy | 0.20 | Share of the agent's side-effecting tools (`write_file`, `delete_file`, `send_email`, `fetch_url`, unknown tools) that need no human approval. | approval config |
| Supply chain | 0.15 | Mean over the agent's MCP servers: +0.5 if unsigned, +0.5 if unpinned or quarantined. | `pins.json`, inventory |
| Anomaly | 0.15 | Highest of: a kill-switch trip in the window (1); the share of recent calls denied; the share of recent calls to tools absent from the agent's own earlier calls. Computed only after `ledger verify` passes; if it fails, anomaly is 1 and flagged. | ledger receipts |

**Why these weights.** Privilege and autonomy decide how much damage an agent can do, and
whether a person stands in the way. Supply chain is weighted lower because the gateway
already enforces pins. Anomaly is lower because the lab's histories are short. These are
judgment calls, not measurements: the score ranks agents and explains why, it is not a
probability, and a few points' difference means nothing.

**Unknown inputs** score 1 and are labelled. A shadow agent has no gateway config, approval
rules or receipts, so it scores high on privilege, autonomy and anomaly: an agent nobody has
registered is treated as risky until shown otherwise.

**Worked example, research-bot** (fresh lab):

| Factor | Value | Why |
| --- | --- | --- |
| Privilege | 0.6 | `delete_file`, `send_email` → tier 1; no credentials found |
| Data sensitivity | 0.3 | `files-read-workspace` permits `/workspace` only; `no-ssh-keys` forbids the key |
| Autonomy | 0.5 | `send_email`, `delete_file` need approval; `write_file`, `fetch_url` don't |
| Supply chain | 0.5 | 4 servers, all pinned, none signed |
| Anomaly | 0 | no denials, no trips |

Score ≈ 42. With a committed key in its sources, privilege becomes 1.0 and the score ≈ 54,
with the finding named in the breakdown.

### Implementation notes (risk engine)

`agentguard risk --inventory inventory.json [--gateway-config] [--policy-dir] [--pins]
[--receipts --public-key [--checkpoints]] [--risk-config config/risk.yaml] [--json]`

- **Missing inputs are unknown.** Without `--gateway-config`, autonomy is unknown; without
  policies, data sensitivity; without `--pins`, supply chain; without `--receipts`, or with no
  `--public-key` to verify them, anomaly. Each scores 1 and is marked.
- **Known zeros aren't unknowns.** An agent with no tools reaches no servers (supply chain 0);
  one with no read tools reads nothing (data sensitivity 0); one with a verified ledger and no
  recent calls has no anomaly (0).
- **The new-tool signal needs a baseline.** It counts only when the agent has at least
  `min_baseline_calls` (20) calls before the window. With fewer, it is skipped and the reason
  says so, rather than scored as worst case: otherwise every new agent's first calls would
  all look anomalous.
- **Denials** count when blocked on the merits (`denial_class` policy or guard). Approval
  timeouts and errors don't.
- **Kill-switch trips** are read from the ledger's control receipts: a kill-list receipt in the
  window that added the agent's name or one of its DIDs (taken from its own calls). The
  breakdown names the category, the receipt's seq and who made it. A `kill-switch` denial
  without such a receipt only counts towards the denied share.
- **Cedar probes** call the gateway's own `CedarCheck`. A probe that errors counts as
  permitted, the riskier answer.
- **Signing.** Nothing in the lab is signed, so every server gets the +0.5 for unsigned.
- **Rounding** is half up (41.5 → 42).

## Control receipts

- The gateway already re-reads `killed.json` when it changes. On each change it also writes a
  `control` receipt: `{kind: "control", action: "kill-list", added, removed, digest}`, where
  `digest` is SHA-256 of the new file's canonical form. Entries name DIDs, agent names and
  revocation ids; the free-text reason is a commitment (option C), like any other attribute
  not on the clear list.
- The check also runs in the gateway's background loop, so a change is recorded even when no
  calls arrive.
- **At startup**, the gateway compares the kill list's digest with the digest in the ledger's
  last `control` receipt. If they differ (or the list is non-empty and no control receipt
  exists), it records a `control` receipt with `while_stopped: true` before serving.
- A budget trip records its kill the same way, with `source: "budget-trip"`.
- `ledger verify` and `ledger.read` treat `control` as a third receipt kind.

### Implementation notes (control receipts)

Code: `gateway/control.py`; the kill list's writers are in `guards/state.py`.

- **Who and what.** Every write to `killed.json` records `last_change: {action, by, at}`.
  `by` is `cli:<OS user>` for `agentguard kill`, `revive` and `guards reset`;
  `gateway:budget` for a budget trip; `lab-harness` for the lab's resets. A hand edit has
  none, so its receipt says `unknown`. Inside Docker the CLI runs as root (`cli:root`).
- **Net changes.** A receipt records the difference since the gateway last looked, named after
  the last write. Two kills in one refresh interval, or several while stopped, become one.
- **When it looks:** on every call, on every refresh tick (`refresh_interval_s`) even with no
  calls, and at startup.
- **Not recorded:** a guard reset of an already empty list changes nothing in it. The budgets
  and taint that a reset clears are in-memory state, not the list.
- **Reasons** (made consistent 2026-10-10). Each kill carries a fixed category in the clear,
  `manual` (the CLI) or `budget` (a trip), or `unknown` for an entry without one, and its
  free-text reason only as a commitment. Control receipts and `kill-switch` denial receipts
  record both the same way. Until then, denial receipts had shown the free text in the clear
  since Phase 4. A change found at startup with no recorded write is `startup-diff`.
- **Pins and quarantines** are recorded the same way, as `action: "pins"`: each new pin and
  each quarantine as it happens (`by: gateway:pins`), and any edit made while the gateway was
  stopped (such as re-approving a server by editing the pins file) at its next start, as
  `change: startup-diff` with an unknown author. Description hashes and the gateway's own
  quarantine reasons are in the clear. Each startup check compares against the last receipt
  of its own action.
- **Measured in Docker** (2026-10-10, all eight attacks): attack 6's trip is a `kill` by
  `gateway:budget` adding 26 entries (the DID and every token revocation id seen for it); the
  reset before attack 7 is a `reset` by `cli:root` removing them. The ledger verifies intact.

## Dashboard

- Views: inventory with risk breakdowns, recent calls (`ledger.read.calls`) with the
  `ledger verify` status, pending approvals, and the kill switch.
- All data access goes through `agentguard.dashboard.data`, which opens files read-only and
  doesn't import `ledger.writer` or any signing key.
- Approve, deny, kill and revive call the same functions as the CLI, moved into one module
  (`agentguard.ops`) so there is a single path. The approver recorded is the OS user, not a
  free-text field.

### Implementation notes (dashboard)

`agentguard dashboard [--receipts --public-key --checkpoints --pins --inventory --state-dir]`
(`uv sync --extra dashboard`); `make dashboard-docker` for the Docker lab.

- **Streamlit 1.64.0**, the newest release at least two weeks old on 2026-10-10, under the
  `dashboard` extra (and the dev dependencies, so its tests always run). The Docker image
  doesn't include it.
- **Server options.** The launcher sets `server.address=127.0.0.1`,
  `browser.gatherUsageStats=false`, `server.enableXsrfProtection=true` and
  `client.toolbarMode=viewer` (which hides Streamlit's "Deploy" button). The page checks all
  four itself and refuses to render under anything else. Checked 2026-10-10: it listened on
  127.0.0.1:8501 only, and the machine's own address got no answer.
- **What it shows** (`dashboard/data.py`): exactly what receipts show. Call rows carry rule
  ids, decisions, summaries, the coarse attributes on the clear list, and "committed (…)" for
  the rest; a raw value in an old Phase 4 receipt shows as "hidden". Pending approvals show
  the tool, agent, coarse attributes and the argument hash, never the arguments
  (`agentguard approvals list` shows those). The kill list shows categories, never reasons.
  Pins show servers, tools and quarantines, never hashes. Credentials show as the scanner
  reports them.
- **Read-only.** `data` never imports the ledger writer, the gateway or `gateway.receipts`;
  the pure receipt helpers moved to `gateway/receipt_fields.py` for that. A test makes the
  ledger, checkpoints, public key and pins read-only, runs every view and every action, and
  checks no file was opened for writing and none changed.
- **Actions** call `agentguard.ops`, which the CLI now calls too: kill and revive as
  `dashboard:<user>` (the CLI is `cli:<user>`), approve and deny as `<user>`. The CLI's
  `--approver` option is gone: approvals are recorded as the OS user on both paths.
- **Docker is view-only.** Pending approvals and the kill list live on the gateway-only
  volume, and the dashboard runs on the host. `make dashboard-docker` copies the ledger,
  checkpoints, public key and pins out of the gateway container with `docker compose cp`
  (reading only) into `run-logs/dashboard-docker/<time>/`, scans an inventory, and serves
  those. The kill list then comes from the last kill-list control receipt, and each action is
  shown as its `docker compose exec gateway agentguard …` command. The public key comes from
  the same lab, so this is a view, not an independent audit: pin a key out of band for that.

## Attack 8

- At test time, a temporary git repo is created with a committed file holding a **canary**
  key: `anthropic-api-key`-shaped, with a visible `AGENTGUARDCANARY` marker and random filler,
  made fresh every run. Nothing key-shaped is committed to this repo.
- An inventory mapping links that repo to research-bot.
- Oracle: the attack succeeds unless the inventory lists the finding (rule id, file, line)
  and research-bot's score rises with that finding named in the breakdown.
- Baseline: there is no scanner, so nothing notices: a strict xfail. As with attack 7, the
  baseline result holds by construction.
- The canary is a demo fixture, not an evaluation payload. Phase 6 makes no detection-rate
  claim. One would need gitleaks' upstream test data at a pinned commit.

## Tests

- **Attack 8:** baseline strict xfail; guarded must detect it.
- **No secret in any output:** canaries in `.env`, Python, MCP config env values and
  arguments, URLs with tokens, binary, unreadable and oversized files. JSON output, human
  output, stderr, log records and error paths must not contain the canary or any 8-character
  piece of it.
- **Read-only and offline:** sockets blocked; file hashes and mtimes unchanged; every open of
  a scanned file is read-only. A key committed and then deleted is found with `--history`.
  The malicious-config repo above runs nothing.
- **Risk:** fixed inputs give exact expected breakdowns; unknown inputs score 1; a failed
  verify gives anomaly 1.
- **Control receipts:** kill, revive, reset and budget trip each produce one; a change made
  while the gateway is stopped is recorded at startup; `verify` passes on them.
- **Dashboard can't write the ledger:** with the ledger file and folder read-only, every view
  and action leaves its bytes and mtime unchanged; no ledger path is opened for writing; the
  dashboard doesn't import the writer or keys; a dashboard kill and a CLI kill give identical
  state.

## Order of work

Each step ends at a checkpoint: stop and report.

1. Scanner (working tree, then `--history`) and privacy tests.
2. Risk engine.
3. Attack 8.
4. Control receipts.
5. Dashboard.
6. Docs (README, roadmap).
