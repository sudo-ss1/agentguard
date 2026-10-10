"""The AgentGuard dashboard page (Streamlit). Start it with `agentguard dashboard`, which sets
the server options below; the page refuses to render under any others.

Views come from `data` (read-only, redacted). Actions call `agentguard.ops`, the functions the
CLI calls, as the operating-system user: kill-list changes become control receipts in the
ledger, approvals are recorded in the call's receipt. Without the gateway's state folder (a
Docker snapshot) the page is view-only and shows the CLI command for each action instead.
"""

import streamlit as st

from agentguard import ops
from agentguard.dashboard import data

# The server must listen on loopback only, send no usage statistics, and check XSRF tokens.
# The viewer toolbar hides Streamlit's "Deploy" button, which links to its cloud service.
REQUIRED_OPTIONS = {
    "server.address": "127.0.0.1",
    "browser.gatherUsageStats": False,
    "server.enableXsrfProtection": True,
    "client.toolbarMode": "viewer",
}
DOCKER = "docker compose exec gateway agentguard"


def server_options_ok() -> list[str]:
    return [
        f"{name} is {st.get_option(name)!r}, must be {want!r}"
        for name, want in REQUIRED_OPTIONS.items()
        if st.get_option(name) != want
    ]


def main() -> None:
    st.set_page_config(page_title="AgentGuard", layout="wide")
    problems = server_options_ok()
    if problems:  # fail closed: never serve this page on other terms
        st.error(
            "Refusing to run: " + "; ".join(problems) + ". Start it with `agentguard dashboard`."
        )
        st.stop()
    src = data.Sources.from_env()
    st.title("AgentGuard")
    status = data.ledger_status(src)
    st.caption(
        f"Ledger: {status['state']}"
        + (f" ({status.get('receipts')} receipts)" if "receipts" in status else "")
        + ("" if src.can_act else " · view-only (no access to the gateway's state)")
    )
    if st.button("Refresh"):
        st.rerun()
    risk_tab, calls_tab, approvals_tab, kill_tab, audit_tab = st.tabs(
        ["Agents and risk", "Recent calls", "Approvals", "Kill switch", "Audit"]
    )
    with risk_tab:
        agents_and_risk(src)
    with calls_tab:
        rows = data.recent_calls(src)
        if rows:
            st.dataframe(rows, use_container_width=True)
        else:
            st.info("No calls recorded.")
    with approvals_tab:
        approvals(src)
    with kill_tab:
        kill_switch(src)
    with audit_tab:
        st.subheader("Ledger verification")
        st.json(status)
        st.subheader("Control receipts (kill list, pins)")
        st.dataframe(data.control_receipts(src), use_container_width=True)
        st.subheader("Pinned MCP servers")
        st.dataframe(data.pins_summary(src), use_container_width=True)


def agents_and_risk(src: data.Sources) -> None:
    results = data.risk(src)
    if not results:
        st.info("No inventory. Run `agentguard scan ... --out inventory.json` and pass it.")
        return
    st.caption("Unknown inputs count as worst case, so unregistered agents rank high by design.")
    st.dataframe(
        [{"agent": r["agent"], "kind": r["kind"], "risk": r["score"]} for r in results],
        use_container_width=True,
    )
    for r in results:
        with st.expander(f"{r['agent']} ({r['kind']}): {r['score']}/100"):
            for name, f in r["factors"].items():
                flag = " · unknown" if f["unknown"] else ""
                st.markdown(
                    f"**{name}** {f['value']:.2f} × {f['weight']:.2f} = {f['points']}{flag}"
                )
                for why in f["why"]:
                    st.markdown(f"- {why}")
    with st.expander("Inventory (as the scanner reported it)"):
        st.json(data.inventory(src))


def approvals(src: data.Sources) -> None:
    pending = data.pending_approvals(src)
    if pending is None:
        st.info("View-only: pending approvals live on the gateway's own volume.")
        commands = ["approvals list", "approvals approve <id>", "approvals deny <id>"]
        st.code("\n".join(f"{DOCKER} {c}" for c in commands))
        return
    if not pending:
        st.info("No pending approvals.")
        return
    st.caption(
        f"Arguments are not shown, only what a receipt would show. Decisions are recorded as "
        f"{ops.os_user()}. `agentguard approvals list` shows the full arguments."
    )
    for r in pending:
        st.markdown(f"**{r['tool']}** by {r['agent']} · {r['why']} · request `{r['id']}`")
        st.json({"attributes": r["attributes"], "args sha256": r["args sha256"]})
        approve, deny, _ = st.columns([1, 1, 6])
        if approve.button("Approve", key=f"approve-{r['id']}"):
            answer(src, r["id"], True)
        if deny.button("Deny", key=f"deny-{r['id']}"):
            answer(src, r["id"], False)


def answer(src: data.Sources, request_id: str, approve: bool) -> None:
    assert src.state_dir is not None
    if ops.decide(src.state_dir, request_id, approve, ops.os_user()):
        st.success(f"{'Approved' if approve else 'Denied'} {request_id} as {ops.os_user()}")
    else:
        st.warning(f"{request_id} is no longer pending (answered, timed out or voided)")


def kill_switch(src: data.Sources) -> None:
    killed = data.kill_list(src)
    st.caption(f"From the {killed['source']}. Reasons are not shown, only their category.")
    st.dataframe(killed["entries"], use_container_width=True)
    if not src.can_act:
        st.info("View-only. Run on the host:")
        st.code(f"{DOCKER} kill --agent <name> --reason '...'\n{DOCKER} revive --agent <name>")
        return
    assert src.state_dir is not None
    with st.form("kill"):
        name = st.text_input("Agent name to stop")
        reason = st.text_input("Reason (committed in receipts, never shown)", "manual kill")
        sure = st.checkbox("Stop this agent now, even though its token is still valid")
        if st.form_submit_button("Kill") and name and sure:
            affected = ops.kill(src.state_dir, ops.operator("dashboard"), reason, agent=name)
            st.success(f"Killed {name} ({len(affected)} DID(s) with recorded tokens)")
    for entry in killed["entries"]:
        if entry["kind"] in ("names", "dids") and st.button(
            f"Revive {entry['id']}", key=f"revive-{entry['kind']}-{entry['id']}"
        ):
            target = {"agent": entry["id"]} if entry["kind"] == "names" else {"did": entry["id"]}
            ops.revive(src.state_dir, ops.operator("dashboard"), **target)
            st.success(f"Revived {entry['id']}")


main()
