"""Which Docker services can reach which secrets and logs (docker-compose.yml).

The gateway alone holds the receipt-signing key and the commitment salts, and alone can write
the ledger. The agent container (the harness) may read receipts and checkpoints, never write
them.
"""

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((REPO / "docker-compose.yml").read_text())
GATEWAY_CONFIG = yaml.safe_load((REPO / "config" / "gateway.yaml").read_text())


def mounts() -> dict[str, list[tuple[str, str, bool]]]:
    """service -> [(volume or host path, container path, read-only)]."""
    out = {}
    for name, service in COMPOSE["services"].items():
        rows = []
        for spec in service.get("volumes", []):
            parts = spec.split(":")
            rows.append((parts[0], parts[1], len(parts) > 2 and "ro" in parts[2].split(",")))
        out[name] = rows
    return out


def services_mounting(volume: str) -> dict[str, bool]:
    """service -> read-only, for every service that mounts `volume`."""
    return {s: ro for s, rows in mounts().items() for v, _, ro in rows if v == volume}


def test_only_the_gateway_mounts_the_signing_key_and_the_salts():
    for volume in ("ledger-key", "receipt-salts", "gateway-state"):
        assert services_mounting(volume) == {"gateway": False}, volume


def test_only_the_gateway_can_write_the_ledger():
    for volume in ("ledger", "ledger-roots"):
        mounted = services_mounting(volume)
        assert mounted.get("gateway") is False, f"the gateway must write {volume}"
        writers = [s for s, ro in mounted.items() if not ro and s != "gateway"]
        assert writers == [], f"{volume} is writable by {writers}"


def test_the_identity_services_keys_stay_with_it():
    assert services_mounting("identity-state") == {"identity": False}
    assert services_mounting("agent-creds") == {"provision": False, "agent": True}


def test_the_gateway_writes_receipts_and_keys_to_those_volumes():
    gateway = {path: volume for volume, path, _ in mounts()["gateway"]}

    def volume_of(path: str) -> str | None:
        matches = [p for p in gateway if path == p or path.startswith(p.rstrip("/") + "/")]
        return gateway[max(matches, key=len)] if matches else None

    assert volume_of(GATEWAY_CONFIG["receipts_path"]) == "ledger"
    assert volume_of(GATEWAY_CONFIG["ledger"]["key_dir"]) == "ledger-key"
    assert volume_of(GATEWAY_CONFIG["ledger"]["roots_dir"]) == "ledger-roots"
    assert volume_of(GATEWAY_CONFIG["salts_path"]) == "receipt-salts"


def test_the_harness_reads_receipts_from_the_ledger_volume():
    agent = {path: volume for volume, path, _ in mounts()["agent"]}
    receipts = COMPOSE["services"]["agent"]["environment"]["RECEIPTS_PATH"]
    assert agent[str(Path(receipts).parent)] == "ledger"


# --- everything the gateway trusts ----------------------------------------------------------

# What the gateway reads and acts on, from its config: pins and quarantines, the kill list and
# approvals (guards.state_dir), the identity trust anchor, its ledger and keys, its policies and
# the config file itself.
TRUSTED = {
    "pins": GATEWAY_CONFIG["pins_path"],
    "guard state (kill list, approvals)": GATEWAY_CONFIG["guards"]["state_dir"],
    "identity trust anchor": GATEWAY_CONFIG["identity_file"],
    "receipts": GATEWAY_CONFIG["receipts_path"],
    "salts": GATEWAY_CONFIG["salts_path"],
    "ledger key": GATEWAY_CONFIG["ledger"]["key_dir"],
    "ledger roots": GATEWAY_CONFIG["ledger"]["roots_dir"],
    "policies": GATEWAY_CONFIG["policy_dir"],
    "config": COMPOSE["services"]["gateway"]["command"][
        COMPOSE["services"]["gateway"]["command"].index("--config") + 1
    ],
}
# The one other writer allowed: `provision` writes the trust anchor once, at setup.
ALLOWED_WRITERS = {"gateway-trust": {"provision"}}


def gateway_volume_of(path: str) -> str | None:
    """The gateway's volume holding `path`, or None if it is in the image."""
    rows = {p: v for v, p, _ in mounts()["gateway"]}
    matches = [p for p in rows if path == p or path.startswith(p.rstrip("/") + "/")]
    return rows[max(matches, key=len)] if matches else None


def test_no_other_container_can_write_anything_the_gateway_trusts():
    for what, path in TRUSTED.items():
        volume = gateway_volume_of(path)
        if volume is None:  # baked into the image: nobody may mount over it
            assert path.startswith("/app/"), f"{what} ({path}) is neither on a volume nor in /app"
            for service, rows in mounts().items():
                for _, target, _ in rows:
                    assert not (path.startswith(target.rstrip("/") + "/") or path == target), (
                        f"{service} mounts {target} over the gateway's {what}"
                    )
            continue
        writers = {s for s, ro in services_mounting(volume).items() if not ro} - {"gateway"}
        assert writers <= ALLOWED_WRITERS.get(volume, set()), (
            f"{what} ({path}, volume {volume}) is writable by {sorted(writers)}"
        )


def test_the_gateway_shares_no_writable_volume_with_the_tools_or_the_agent():
    gateway_volumes = {v for v, _, _ in mounts()["gateway"]}
    assert "lab-state" not in gateway_volumes
    for service in ("files", "web", "email", "weather", "agent"):
        shared = {v for v, _, ro in mounts()[service] if not ro} & gateway_volumes
        assert shared == set(), f"{service} can write the gateway's {sorted(shared)}"


def test_the_harness_reads_pins_from_the_gateways_pins_volume():
    agent = {path: (volume, ro) for volume, path, ro in mounts()["agent"]}
    pins = COMPOSE["services"]["agent"]["environment"]["PINS_PATH"]
    assert agent[str(Path(pins).parent)] == ("gateway-pins", True)
    assert pins == GATEWAY_CONFIG["pins_path"]
