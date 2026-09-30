"""Injection scanning on tool results: stripping, Vigil rules, tool-name lures, the classifier.

Inputs come from files: the attack 1 page, benign pages (the lab's, and a real Wikipedia
article), deepset's train split sample, and Vigil's own rule file. The only literal inputs here
are structural (markup, CSS, Unicode code points) or built from the gateway config.
"""

import json
import re
import shutil
import time
from pathlib import Path

import pytest
import yaml

from agentguard.guards.classifier import ClassifierConfig, ClassifierScore
from agentguard.guards.result_scan import (
    VIGIL_DIR,
    InjectionConfig,
    ResultScanner,
    VigilRules,
    hidden_text,
    strip_hidden,
)
from tests.gateway_helpers import add_tool, call, ctx, identity, receipts

REPO = Path(__file__).resolve().parents[1]
ATTACK_PAGE = (REPO / "lab/evil_site/recipe.html").read_text()
BENIGN_PAGES = {
    "benign_page.html": (REPO / "tests/data/benign_page.html").read_text(),
    "lab index.html": (REPO / "lab/evil_site/index.html").read_text(),
    "wikipedia_tomato.html": (REPO / "tests/data/wikipedia_tomato.html").read_text(),
}
DEEPSET = json.loads((REPO / "tests/data/deepset_prompt_injections_train_sample.json").read_text())[
    "data"
]


def gateway_tool_names() -> set[str]:
    agents = yaml.safe_load((REPO / "config/gateway.yaml").read_text())["agents"]
    return {t for a in agents.values() for t in a["tools"]}


TOOL = sorted(gateway_tool_names())[0]  # any tool name from the config


def tags(text: str) -> str:
    """Encode ASCII as invisible Unicode tag characters."""
    return "".join(chr(0xE0000 + ord(c)) for c in text)


def vigil_literal() -> str:
    """A literal string from one of Vigil's own vendored rules, read from the file."""
    rule = (VIGIL_DIR / "guidance.yar").read_text()
    return re.findall(r'\$\w*\s*=\s*"([^"]+)"', rule)[0]


def scanner(classifier=None, enabled=False, **cfg):
    config = InjectionConfig(classifier=ClassifierConfig(enabled=enabled, timeout_s=0.3, **cfg))
    return ResultScanner(config, gateway_tool_names(), classifier)


def scan(text, tool="fetch_url", server="web", **kw):
    visible, result = scanner(**kw).scan(tool, server, [text])
    return visible[0], result


# --- Vigil rules ---------------------------------------------------------------------------------


def test_vigil_loads_the_five_pinned_rule_files():
    assert VigilRules().commit == "f2b4c134d060bae81d29fad07003f3c657e63fc8"
    assert len(json.loads((VIGIL_DIR / "MANIFEST.json").read_text())["rules_used"]) == 5


def test_a_modified_rule_file_is_refused(tmp_path):
    copy = tmp_path / "vigil"
    shutil.copytree(VIGIL_DIR, copy)
    target = copy / json.loads((copy / "MANIFEST.json").read_text())["rules_used"][0]
    target.write_text(target.read_text() + "\n// edited\n")
    with pytest.raises(ValueError, match="pinned hash"):
        VigilRules(copy)


# --- benign real pages: the goal is 0 withheld, 0 tainted ----------------------------------------


@pytest.mark.parametrize("name", sorted(BENIGN_PAGES))
def test_benign_pages_are_never_withheld_or_taint(name):
    _, result = scan(BENIGN_PAGES[name])
    assert not result.withhold and not result.taint and result.findings == []


def test_the_real_page_is_cut_to_the_cap_and_keeps_its_visible_text():
    """The 767 KB article is longer than the scan cap: only its first 64 KiB is scanned and
    passed on, the receipt says so, and it is still neither withheld nor tainted."""
    visible, result = scan(BENIGN_PAGES["wikipedia_tomato.html"])
    assert result.action == "truncated" and not result.withhold and not result.taint
    assert result.record()["truncated"]["kept_chars"] == 64 * 1024
    assert "<!--" not in visible and visible.lower().count("tomato") > 20
    assert visible.endswith("KiB]")  # the agent is told the result was cut


# --- stripping -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("markup", "category"),
    [
        ('<p style="font-size:0">words here</p>', "css-hidden-text"),
        ('<p style="visibility: hidden">words here</p>', "css-hidden-text"),
        ('<p style="color:#fff; background-color:#fff">words here</p>', "css-hidden-text"),
        ('<p style="position:absolute; left:-9999px">words here</p>', "offscreen-text"),
        ("<div hidden>words here</div>", "css-hidden-text"),
        ('<style>.x { display: none }</style><span class="x">words here</span>', "css-hidden-text"),
        ("before<!-- some words here -->after", "html-comment"),
        (f"visible{tags('words')}", "unicode-tags"),
    ],
)
def test_hidden_content_is_stripped(markup, category):
    stripped = strip_hidden(markup)
    assert category in [c for c, _ in stripped.removed]
    assert "words" not in stripped.visible


def _equivalence_inputs():
    inputs = dict(BENIGN_PAGES, attack=ATTACK_PAGE)
    page = BENIGN_PAGES["wikipedia_tomato.html"]
    inputs.update({f"tomato {kb} KB": page[: kb * 1024] for kb in (2, 10, 30, 60, 200)})
    inputs.update({f"deepset {i}": r["text"] for i, r in enumerate(DEEPSET)})
    inputs.update(
        {
            "nested": 'a<div style="display:none">x<span hidden>y</span>z</div>b',
            "unclosed": 'keep<div style="display:none">never closed',
            "class rule": '<style>.x { display: none }</style><span class="x">w</span>',
            "comment": "before<!-- some words here -->after",
            "json with <": '{"note": "1 < 2 and 3 > 2"}',
            "script": '<script>var s = "<div style=display:none>";</script><p>ok</p>',
        }
    )
    return inputs


def test_fast_tokenizer_finds_the_same_spans_as_html_parser():
    """The gateway's tokenizer must match the original html.parser version exactly."""
    from agentguard.guards.result_scan import _hidden_spans
    from tests.reference_hidden_spans import reference_spans

    diffs = [k for k, t in _equivalence_inputs().items() if _hidden_spans(t) != reference_spans(t)]
    assert diffs == []


def test_non_html_text_is_left_byte_identical():
    text = '{"note": "1 < 2 and 3 > 2", "x": [1, 2]}'
    assert strip_hidden(text).visible == text


def test_results_under_the_cap_are_not_cut():
    _, result = scan(BENIGN_PAGES["benign_page.html"])
    assert result.truncated is None and "truncated" not in result.record()


def test_the_cap_counts_a_duplicated_string_once():
    page = BENIGN_PAGES["wikipedia_tomato.html"]
    visible, result = scanner().scan("fetch_url", "web", [page, page])
    assert visible[0] == visible[1]
    assert result.truncated == {"original_chars": len(page), "kept_chars": 64 * 1024}


def test_a_hidden_element_cut_by_the_cap_stays_hidden():
    """Fail closed at the boundary: an element that opens hidden before the cap and would close
    after it is treated as hidden to the end."""
    head = "<p>" + "visible words " * 10 + "</p>"
    hidden = '<div style="display:none">' + "x" * 200 + "</div><p>after</p>"
    config = InjectionConfig(max_result_chars=len(head) + 50)
    visible, result = ResultScanner(config, gateway_tool_names()).scan(
        "fetch_url", "web", [head + hidden]
    )
    assert visible[0].startswith(head) and "x" * 10 not in visible[0]
    assert result.truncated and result.stripped.get("css-hidden-text") == 1


def test_nested_hidden_elements_are_removed_once_as_a_whole():
    stripped = strip_hidden('a<div style="display:none">x<span hidden>y</span>z</div>b')
    assert stripped.visible == "ab" and len(stripped.removed) == 1


def test_duplicate_strings_in_a_result_are_stripped_but_counted_once():
    visible, result = scanner().scan("fetch_url", "web", [ATTACK_PAGE, ATTACK_PAGE])
    assert visible[0] == visible[1] and "display:none" not in visible[1]
    assert result.stripped == {"css-hidden-text": 1}


def test_an_unclosed_hidden_element_hides_the_rest():
    assert strip_hidden('keep<div style="display:none">never closed').visible == "keep"


def test_ordinary_zero_width_characters_are_stripped_without_a_finding():
    visible, result = scan("plain​text with a zero‍width joiner")
    assert visible == "plaintext with a zerowidth joiner"
    assert result.stripped == {"zero-width": 1} and not result.taint and result.findings == []
    assert hidden_text("plain​text") == []  # not reported as hidden content


def test_hidden_text_alone_is_stripped_but_does_not_taint():
    visible, result = scan('<p>shown</p><div style="display:none">some hidden words</div>')
    assert result.action == "stripped" and not result.taint and "hidden" not in visible


# --- the combined signal -------------------------------------------------------------------------


def test_attack_page_is_stripped_and_taints_because_its_hidden_text_names_tools():
    visible, result = scan(ATTACK_PAGE)
    assert result.action == "stripped" and result.taint
    assert {"hidden:tool-name-lure:read_file", "hidden:tool-name-lure:send_email"} <= set(
        result.findings
    )
    assert "Lemon Cake" in visible and "display:none" not in visible


def test_a_tool_name_alone_in_visible_text_is_not_a_signal():
    visible, result = scan(f"<p>Our docs describe {TOOL} in detail.</p>")
    assert not result.taint and result.findings == [] and TOOL in visible


def test_a_visible_tool_name_plus_other_hidden_content_taints():
    _, result = scan(f"<p>see {TOOL}</p><!-- some words in a comment -->")
    assert result.taint and f"tool-name-lure:{TOOL}" in result.findings


def test_tool_name_smuggled_in_tag_characters_taints():
    visible, result = scan(f"a normal sentence{tags(TOOL)}")
    assert result.taint and f"hidden:tool-name-lure:{TOOL}" in result.findings
    assert visible == "a normal sentence"


def test_vigil_match_in_visible_text_withholds_and_taints():
    _, result = scan(f"<p>{vigil_literal()}</p>")
    assert result.withhold and result.taint
    assert any(f.startswith("vigil:") for f in result.findings)


def test_vigil_match_inside_hidden_text_is_stripped_and_taints():
    _, result = scan(f'<p>ok</p><div style="display:none">{vigil_literal()}</div>')
    assert not result.withhold and result.taint
    assert any(f.startswith("hidden:vigil:") for f in result.findings)


# --- deepset samples (train split) ---------------------------------------------------------------


def test_deepset_samples_are_never_withheld_or_tainted_by_structure():
    """deepset rows are plain-text prompts; structural detectors should leave them alone. Vigil
    counts are printed for information; rates belong to the eval harness (test split)."""
    results = [scan(r["text"])[1] for r in DEEPSET]
    assert [r for r in results if r.withhold or r.taint] == []
    injections = [r["text"] for r in DEEPSET if r["label"] == 1]
    vigil = VigilRules()
    flagged = sum(1 for t in injections if vigil.match(t))
    print(f"\nVigil on deepset train sample: {flagged}/{len(injections)} injections flagged")


# --- classifier path -----------------------------------------------------------------------------


class FakeClassifier:
    name, revision = "fake", "0"

    def __init__(self, probability=0.0, complete=True, delay=0.0, fail=False):
        self.probability, self.complete, self.delay, self.fail = probability, complete, delay, fail
        self.calls = 0

    def score(self, text):
        self.calls += 1
        if self.fail:
            raise RuntimeError("model crashed")
        time.sleep(self.delay)
        return ClassifierScore(self.probability, 1, self.complete)


def test_classifier_runs_only_on_untrusted_results():
    clf = FakeClassifier(0.01)
    scanner(clf, enabled=True).scan("read_file", "files", ["text"])
    assert clf.calls == 0
    scanner(clf, enabled=True).scan("fetch_url", "web", ["text"])
    scanner(clf, enabled=True).scan("get_weather", "weather", ["text"])  # third-party server
    assert clf.calls == 2


def test_classifier_flag_withholds_and_taints():
    _, result = scan("text", classifier=FakeClassifier(0.97), enabled=True)
    assert result.withhold and result.taint and result.record()["classifier"]["score"] == 0.97


@pytest.mark.parametrize(
    ("clf", "error"),
    [
        (FakeClassifier(fail=True), "classifier failed"),
        (FakeClassifier(delay=1.0), "timed out"),
        (FakeClassifier(0.01, complete=False), "longer than"),
    ],
)
def test_classifier_problems_fail_closed(clf, error):
    _, result = scan("text", classifier=clf, enabled=True)
    assert result.withhold and error in result.error


def test_classifier_that_cannot_load_fails_closed(tmp_path):
    _, result = scan("text", enabled=True, model_dir=tmp_path)
    assert result.withhold and "failed to load" in result.error


# --- at the gateway ------------------------------------------------------------------------------

FETCHER = identity("research-bot", tools=("fetch_url", "send_email", "read_file"))


async def test_attack_page_reaches_the_agent_stripped_and_taints(gateway):
    add_tool(gateway, "fetch_url", "web", ["url"]).responses["fetch_url"] = ATTACK_PAGE
    result = await gateway.on_call_tool(ctx(FETCHER), call("fetch_url", url="http://x.test/r"))
    text = result.content[0].text
    assert not result.is_error and "Lemon Cake" in text and "display:none" not in text
    assert gateway.taint.is_tainted(FETCHER.profile.did)
    (receipt,) = receipts(gateway)
    record = receipt["result_scan"]
    assert receipt["decision"] == "allow" and record["action"] == "stripped" and record["taint"]
    assert record["stripped"] == {"css-hidden-text": 1}
    assert set(record["stripped_content"]) == {"commitment"}
    # the hidden content itself is nowhere in the receipt log: no 24-character run of its text
    hidden = re.sub(r"<[^>]+>", " ", strip_hidden(ATTACK_PAGE).removed[0][1])
    hidden = re.sub(r"\s+", " ", hidden).strip()
    chunks = [hidden[i : i + 24] for i in range(0, len(hidden) - 24, 12)]
    log = gateway.config.receipts_path.read_text()
    assert len(chunks) > 5 and not any(c in log for c in chunks)


async def test_benign_page_reaches_the_agent_untouched(gateway):
    page = BENIGN_PAGES["benign_page.html"]
    add_tool(gateway, "fetch_url", "web", ["url"]).responses["fetch_url"] = page
    result = await gateway.on_call_tool(ctx(FETCHER), call("fetch_url", url="http://x.test/b"))
    assert not result.is_error and result.content[0].text == page
    assert not gateway.taint.is_tainted(FETCHER.profile.did)
    assert receipts(gateway)[0]["result_scan"]["action"] == "passed"


def test_scanning_can_be_switched_off_for_the_eval_control_only():
    config = InjectionConfig(enabled=False)
    visible, result = ResultScanner(config, gateway_tool_names()).scan(
        "fetch_url", "web", [ATTACK_PAGE]
    )
    assert visible == [ATTACK_PAGE] and not result.taint and result.action == "passed"
    assert InjectionConfig().enabled  # on by default
