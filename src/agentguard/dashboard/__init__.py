"""The dashboard (Phase 6): inventory and risk, recent calls, pending approvals and the kill
switch. See docs/phase6-design.md.

- `data` builds every view, read-only and redacted as receipts are. It never imports the
  ledger writer, and nothing in it writes.
- `app` is the Streamlit page. Its actions call `agentguard.ops`, the same functions as the CLI.
"""
