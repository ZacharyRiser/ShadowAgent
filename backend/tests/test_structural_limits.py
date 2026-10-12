"""Pins the measured structural limits of the bag-of-n-grams model.

These numbers come from ``tools/bench_structural_limits.py`` and are pinned on
purpose: the roadmap's "add an embedding layer" item (9) is justified or killed
by them, so a silent change in either direction has to fail a test rather than
quietly weaken the argument.

The counts are *observations*, not targets. If a fix lands, these tests fail and
must be updated to the new measurement — that is the intended behaviour. Never
relax an assertion to make it pass.
"""

from __future__ import annotations

import pytest

from app import semantic
from app.semantic import extract_features, semantic_threshold, score_text
from app.semantic_corpus import BENIGN_CALIBRATION_PROBES, CORPUS
from app.semantic_limit_probes import MENTION_VS_USE_PAIRS, injection_probes
from security_engine import semantic_intent_check

# Coverage below this means most of a text's n-grams carry no learned weight, so
# its score is shrunk toward the out-of-domain prior instead of computed from
# evidence.
LOW_COVERAGE = 0.5
FEW_FEATURES = 10


def _fused_blocked(text: str) -> bool:
    return not semantic_intent_check(text).allowed


def _missed(family: str) -> list[str]:
    return [
        text
        for probe_family, _language, text in injection_probes()
        if probe_family == family and not _fused_blocked(text)
    ]


def _coverage(text: str, model) -> float:
    features = extract_features(text)
    if not features:
        return 0.0
    matched = sum(1 for bucket in features if bucket in model.weights)
    return matched / len(features)


@pytest.fixture(scope="module")
def model():
    loaded = semantic._load_model()
    assert loaded is not None, "semantic model artifact missing"
    return loaded


def test_probe_sets_are_disjoint_from_training_material() -> None:
    """A probe that is also training material measures memorisation."""
    training_material = {text for _label, _tag, text in CORPUS} | set(BENIGN_CALIBRATION_PROBES)

    attack_overlaps = [
        text for _family, _language, text in injection_probes() if text in training_material
    ]
    pair_overlaps = [
        text
        for _intent, _language, benign, attack in MENTION_VS_USE_PAIRS
        for text in (benign, attack)
        if text in training_material
    ]

    assert attack_overlaps == []
    assert pair_overlaps == []


def test_mention_and_use_are_separated_without_false_positives(model) -> None:
    """The strongest argument for embeddings is mention-versus-use.

    It does not hold here: the model separates all in-scope pairs and blocks
    none of the benign halves. If this ever regresses, the embedding-layer
    argument gains real evidence.
    """
    threshold = semantic_threshold()
    in_scope = [row for row in MENTION_VS_USE_PAIRS if row[0] == "prompt_injection"]
    assert len(in_scope) == 5

    separated = 0
    false_positives = []
    for _intent, _language, benign, attack in in_scope:
        benign_allowed = semantic_intent_check(benign).allowed
        attack_blocked = not semantic_intent_check(attack).allowed
        if not benign_allowed:
            false_positives.append(benign)
        if benign_allowed and attack_blocked:
            separated += 1

    assert false_positives == [], "benign discussion text must not be blocked"
    assert separated == 5, "measured 5/5 in-scope pairs separated"
    # The benign halves must also stay far below the threshold, not merely under
    # it: a pair separated by 0.001 is luck, not discrimination.
    margins = [threshold - score_text(benign) for _i, _l, benign, _a in in_scope]
    assert min(margins) > 0.4


def test_inflection_probe_recall_is_still_six_of_thirteen() -> None:
    """Measured 2026-09-20: same intent, different morphology is half-missed."""
    probes = [row for row in injection_probes() if row[0] == "inflection"]
    missed = _missed("inflection")

    assert len(probes) == 13
    assert len(missed) == 7, "measured 6/13 blocked"


def test_isolated_syntax_probe_recall_is_still_two_of_eight() -> None:
    """Measured 2026-09-20: a different sentence shape is the worst family."""
    probes = [row for row in injection_probes() if row[0] == "isolated_syntax"]
    missed = _missed("isolated_syntax")

    assert len(probes) == 8
    assert len(missed) == 6, "measured 2/8 blocked"


def test_no_missed_probe_is_explained_by_an_empty_representation(model) -> None:
    """Every miss produces a usable representation but lacks learned weights.

    This is the load-bearing measurement for roadmap item 9: the misses are
    *unseen n-grams* (data-shaped), not texts the architecture cannot represent.
    An embedding layer buys representation, so it is the wrong fix for them.
    """
    missed = [
        (family, language, text)
        for family, language, text in injection_probes()
        if not _fused_blocked(text)
    ]
    assert missed, "no misses left; roadmap item 9 must be re-evaluated from scratch"

    empty_representations = [
        text for _family, _language, text in missed if len(extract_features(text)) < FEW_FEATURES
    ]
    assert empty_representations == [], (
        "a miss with an empty representation would be an architecture argument"
    )

    well_covered = [
        text for _family, _language, text in missed if _coverage(text, model) >= LOW_COVERAGE
    ]
    assert well_covered == [], (
        "a miss whose n-grams are mostly known would mean the model saw this wording "
        "and still scored it benign — that is an architecture argument, not a data one"
    )
