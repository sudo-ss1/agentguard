"""Discovery scanner (Phase 6): an inventory, or AI bill of materials, of agent-related things
in local repos and MCP client configs. See docs/phase6-design.md.

It is read-only and local: files are opened read-only, nothing is fetched, and no code from a
scanned repo is run. A credential is reported as its rule id, file, line and a keyed
fingerprint, never as the matched text.
"""
