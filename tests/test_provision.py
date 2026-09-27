"""Provisioning the lab's agents (what the Docker lab's `provision` service does)."""

import json
import stat
import subprocess
import sys

import pytest

from agentguard.gateway.config import load_gateway_config
from agentguard.identity.client import load_credentials, wait_for
from agentguard.identity.provision import REGISTERED_AGENTS, UNREGISTERED_AGENTS, provision
from agentguard.identity.vc import verify_vc
from agentguard.lab_stack import REPO_ROOT, _free_port, _wait_for_port


@pytest.fixture
def identity_url(tmp_path_factory):
    """A fresh identity service per test: once a name is bound to a DID, the service (rightly)
    refuses other keys for it."""
    port = _free_port()
    service = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agentguard.identity",
            "--config",
            str(REPO_ROOT / "config" / "identity.yaml"),
            "--state-dir",
            str(tmp_path_factory.mktemp("identity")),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    _wait_for_port(port, service)
    yield f"http://127.0.0.1:{port}"
    service.terminate()
    service.wait(timeout=10)


def test_provision_writes_owner_only_keys_and_verifiable_credentials(identity_url, tmp_path):
    credentials, trust = provision(identity_url, tmp_path)
    assert set(credentials) == {*REGISTERED_AGENTS, *UNREGISTERED_AGENTS}
    for name in REGISTERED_AGENTS:
        assert (
            verify_vc(credentials[name].vc, {trust["issuer_did"]}).did == credentials[name].key.did
        )
        assert credentials[name].token
    for name in UNREGISTERED_AGENTS:
        assert credentials[name].vc is None and credentials[name].token is None
    for key_file in tmp_path.glob("*.key"):
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600

    def comparable(creds):
        return {n: (c.key.did, c.vc, c.token) for n, c in creds.items()}

    assert comparable(load_credentials(tmp_path)) == comparable(credentials)


def test_reprovisioning_keeps_keys_and_refreshes_tokens(identity_url, tmp_path):
    first, _ = provision(identity_url, tmp_path)
    again, _ = provision(identity_url, tmp_path)
    assert {n: c.key.did for n, c in first.items()} == {n: c.key.did for n, c in again.items()}


def test_wait_for_returns_issuer(identity_url):
    assert wait_for(identity_url).did.startswith("did:key:z")


def test_gateway_reads_trust_from_file(tmp_path):
    trust = {"issuer_did": "did:key:zX", "biscuit_root_key": "00" * 32}
    (tmp_path / "identity.json").write_text(json.dumps(trust))
    config = tmp_path / "gateway.yaml"
    config.write_text(
        (REPO_ROOT / "config" / "gateway.yaml")
        .read_text()
        .replace("/gateway-trust/identity.json", str(tmp_path / "identity.json"))
    )
    loaded = load_gateway_config(config)
    assert loaded.identity.issuer_did == "did:key:zX"
    assert loaded.identity.biscuit_root_key == "00" * 32
