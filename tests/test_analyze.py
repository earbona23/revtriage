"""End-to-end: the pipeline over the corpus, and the free/PRO invariant.

The single most important assertion in this file is `test_pro_extended_rules_are_additive`:
it proves, by running the same file with and without a PRO licence, that the score does
not move. That is the guarantee the product makes — PRO adds detail, never a verdict.
"""

from __future__ import annotations

import os

from revtriage.analyze import FEATURE_EXTENDED_RULES, FEATURE_SANDBOX, analyze
from revtriage.license import keys
from revtriage.license.verify import build_token, verify_token
from revtriage.scoring import compute_score


def test_benign_control_scores_benign(corpus):
    triage = analyze(corpus["benign_readme.txt"], name="benign_readme.txt")
    assert triage.score.verdict == "benign"
    assert triage.matches == [] or all(m.capability == "command-and-control" for m in triage.matches)


def test_powershell_dropper_is_malicious(corpus):
    triage = analyze(corpus["powershell_dropper.ps1"], name="powershell_dropper.ps1")
    assert triage.score.verdict in ("malicious", "likely-malicious")
    # The decoded C2 URL must be surfaced with the layer it came from (not L0).
    c2 = [i for i in triage.indicators if i.type == "url"]
    assert c2 and any(i.layer != "L0" for i in c2)


def test_injector_shows_injection_capability(corpus):
    triage = analyze(corpus["fake_injector.exe"], name="fake_injector.exe")
    assert "injection" in triage.capabilities


def test_every_sample_produces_a_score(corpus):
    for name, data in corpus.items():
        triage = analyze(data, name=name)
        assert triage.score is not None
        assert 0 <= triage.score.value <= 100


def test_sandbox_feature_is_always_gated(corpus):
    triage = analyze(corpus["powershell_dropper.ps1"], name="powershell_dropper.ps1")
    sandbox = next(g for g in triage.gated if g.name == FEATURE_SANDBOX)
    assert sandbox.status == "skipped"
    assert "never executes" in sandbox.reason


def _pro_license(features=("*",)):
    seed = os.urandom(32)
    payload = {
        "format": "revtriage-pro",
        "version": 1,
        "subject": "Test",
        "tier": "pro",
        "features": list(features),
        "expires": None,
    }
    token = build_token(payload, seed)
    return verify_token(token, public_key=keys.public_from_seed(seed))


def test_pro_extended_rules_are_additive(corpus):
    # clr_loader.bin is the ONLY sample that fires an extended rule. Using any other one
    # makes this test pass because nothing happened, which is how a guarantee quietly
    # stops being tested: the assertions still read correctly and prove nothing.
    data = corpus["clr_loader.bin"]
    free = analyze(data, name="clr_loader.bin")
    pro = analyze(data, name="clr_loader.bin", license_result=_pro_license())

    # The core verdict and score are identical with and without the licence.
    assert pro.score.value == free.score.value
    assert pro.score.verdict == free.score.verdict

    # PRO ran the extended rules (status ok), free skipped them.
    free_gate = next(g for g in free.gated if g.name == FEATURE_EXTENDED_RULES)
    pro_gate = next(g for g in pro.gated if g.name == FEATURE_EXTENDED_RULES)
    assert free_gate.status == "skipped"
    assert pro_gate.status == "ok"

    # And PRO may add matches (additive), never remove them.
    free_rules = {m.rule_id for m in free.matches}
    pro_rules = {m.rule_id for m in pro.matches}
    assert free_rules <= pro_rules

    # Non-vacuity: PRO must actually have found something extra here, or every assertion
    # above is satisfied by an empty difference.
    extra = pro_rules - free_rules
    assert extra, "no extended rule fired: this test would pass with the guarantee removed"
    assert all(rule.startswith("ext.") for rule in extra)


def test_the_score_freeze_is_load_bearing_not_a_coincidence(corpus):
    """The scores match because analyze() freezes the number before extended rules run —
    not because the extended matches happen to be worth nothing.

    Without this, `test_pro_extended_rules_are_additive` still passes if someone moves the
    score computation after the extended pass, provided the extra matches add zero. This
    test asserts the counterfactual: scoring the PRO match set gives a DIFFERENT number,
    so the freeze is the only reason the verdict holds still.
    """
    data = corpus["clr_loader.bin"]
    free = analyze(data, name="clr_loader.bin")
    pro = analyze(data, name="clr_loader.bin", license_result=_pro_license())

    would_be = compute_score(pro.matches)
    assert would_be.value != free.score.value
    assert would_be.value > free.score.value
    # And it is not a rounding difference: it crosses a verdict band.
    assert would_be.verdict != free.score.verdict
    # Yet what the tool actually reports is the free number, on both tiers.
    assert pro.score.value == free.score.value
    assert pro.score.verdict == free.score.verdict


def test_unlicensed_extended_is_skipped_with_reason(corpus):
    triage = analyze(corpus["fake_injector.exe"], name="fake_injector.exe")
    gate = next(g for g in triage.gated if g.name == FEATURE_EXTENDED_RULES)
    assert gate.status == "skipped"
    assert gate.reason
