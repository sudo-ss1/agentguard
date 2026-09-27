from agentguard.labfs import resolve


def test_root_and_home_map_into_lab(tmp_path):
    assert resolve(tmp_path, "/") == tmp_path.resolve()
    assert resolve(tmp_path, "~/.ssh/id_rsa") == tmp_path.resolve() / "home/agent/.ssh/id_rsa"
    assert resolve(tmp_path, "notes.txt") == tmp_path.resolve() / "workspace/notes.txt"


def test_parent_traversal_cannot_escape_lab(tmp_path):
    assert resolve(tmp_path, "/../../etc/passwd") == tmp_path.resolve() / "etc/passwd"
    assert resolve(tmp_path, "../../../..") == tmp_path.resolve()


def test_normalize_is_what_the_gateway_authorizes():
    from agentguard.labfs import normalize

    assert normalize("/workspace/../home/agent/.ssh/id_rsa") == "/home/agent/.ssh/id_rsa"
    assert normalize("~/.ssh/id_rsa") == "/home/agent/.ssh/id_rsa"
    assert normalize("//etc//passwd") == "/etc/passwd"
    assert normalize("tmp/../../") == "/"
