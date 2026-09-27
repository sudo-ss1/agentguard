from agentguard.agent.scripted import _fill


def test_fill_substitutes_results_and_site():
    args = {"url": "{evil_site}/x", "body": "{results[1]}", "n": 3}
    assert _fill(args, {"evil_site": "http://e", "results": ["a", "b"]}) == {
        "url": "http://e/x",
        "body": "b",
        "n": 3,
    }
