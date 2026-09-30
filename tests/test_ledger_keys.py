"""The receipt-signing key: created once, owner-only, public half exported alone."""

import json
import stat

from agentguard.ledger import keys


def test_the_key_is_created_owner_only_and_reused(tmp_path):
    key_dir = tmp_path / "ledger-key"
    key = keys.load_or_create(key_dir)
    path = key_dir / keys.SIGNING_KEY_FILE
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(key_dir.stat().st_mode) == 0o700
    assert keys.load_or_create(key_dir).did == key.did


def test_the_export_holds_only_the_public_key(tmp_path):
    key = keys.load_or_create(tmp_path / "key")
    exported = keys.export_public(key, tmp_path / "roots")
    assert json.loads(exported.read_text()) == {"did": key.did}
    assert key.seed.hex() not in exported.read_text()
    assert keys.load_public(exported) == key.public_key
    assert keys.load_public(key.did) == key.public_key
    assert keys.did_for(key.public_key) == key.did
