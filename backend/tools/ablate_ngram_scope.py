"""Ablation: is the character-n-gram scope fix actually a win, or a trade?

The v4 change makes within-word character 3/4-grams apply only to *non-word*
tokens (tokens containing digits or non-ASCII characters), where they encode
homoglyph / leetspeak obfuscation, instead of to every token, where on a small
corpus they mostly memorise generic English substrings (``c3:ere`` from
where/were/here reached weight +5.27 and dragged every English text toward the
threshold).

A claim like "the fix helps" is only meaningful if it is measured against the
metric that matters. Plain held-out recall is not that metric — an arbitrarily
low threshold raises recall while letting benign traffic through. The metric is
**the highest held-out injection recall reachable with zero false positives**
across the held-out benign split *and* the external benign calibration probes,
i.e. the best recall a deployable (provably zero-FP) threshold could buy.

This tool trains both policies on the identical stratified split and reports
that number side by side, so the comparison is apples-to-apples and the report's
headline figure stays re-derivable.

Usage (from ``backend/``):
    python tools/ablate_ngram_scope.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app.semantic as semantic  # noqa: E402
from app.semantic import extract_features, score_features  # noqa: E402
from app.semantic_corpus import (  # noqa: E402
    BENIGN_CALIBRATION_PROBES,
    CORPUS,
    KNOWN_FALSE_POSITIVES,
    stratified_split,
)
from tools.train_semantic_model import _train  # noqa: E402

# Thresholds printed for reference only; the decision metric is the swept one.
REFERENCE_THRESHOLDS = (0.85, 0.90, 0.95)


def _best_zero_fp_threshold(
    injection_scores: list[float],
    benign_scores: list[float],
) -> tuple[float, float]:
    """Highest recall over ``injection_scores`` at a threshold with no benign hit.

    Sweeps candidate thresholds over the sorted benign ceiling; returns
    ``(threshold, recall)`` for the most permissive zero-false-positive cut.
    """

    if not injection_scores:
        return 1.0, 0.0
    # A candidate threshold only needs to be tested just above each benign
    # score (below the lowest benign score, everything passes and any benign
    # hit would already be counted).
    candidates = sorted({score + 1e-6 for score in benign_scores} | {0.0})
    best_threshold, best_recall = 1.0, 0.0
    for candidate in candidates:
        false_positives = sum(1 for score in benign_scores if score >= candidate)
        if false_positives:
            continue
        recall = sum(1 for score in injection_scores if score >= candidate) / len(injection_scores)
        if recall > best_recall:
            best_threshold, best_recall = candidate, recall
    return best_threshold, best_recall


def _run(label: str, char_ngram_all_tokens: bool) -> dict[str, object]:
    original = semantic._is_plain_word
    semantic._is_plain_word = (lambda _token: False) if char_ngram_all_tokens else original
    try:
        train, heldout = stratified_split()
        weights, bias, _ = _train(train, epochs=100, lr0=0.5, l2_lambda=1e-6)

        def score(text: str) -> float:
            return score_features(weights, bias, extract_features(text))

        heldout_injection = [score(t) for label, _, t in heldout if label == "injection"]
        heldout_benign = [score(t) for label, _, t in heldout if label == "benign"]
        probe_scores = [score(probe) for probe in BENIGN_CALIBRATION_PROBES]
    finally:
        semantic._is_plain_word = original

    benign_for_sweep = heldout_benign + probe_scores
    threshold, recall = _best_zero_fp_threshold(heldout_injection, benign_for_sweep)

    print(f"\n=== {label} ===")
    print(
        f"  nuisance ceiling: held-out benign={max(heldout_benign):.3f}  "
        f"probes={max(probe_scores):.3f}  "
        f"combined={max(benign_for_sweep):.3f}"
    )
    print(
        f"  best deployable (zero FP on held-out benign + {len(probe_scores)} probes): "
        f"threshold={threshold:.4f}  recall={recall:.3f}"
    )
    for reference in REFERENCE_THRESHOLDS:
        true_positives = sum(1 for score_value in heldout_injection if score_value >= reference)
        false_positives = sum(1 for score_value in benign_for_sweep if score_value >= reference)
        print(
            f"  @ {reference:.2f}: held-out recall={true_positives / len(heldout_injection):.3f}  "
            f"FP={false_positives} (held-out benign + probes)"
        )
    return {
        "label": label,
        "ceiling": max(benign_for_sweep),
        "threshold": threshold,
        "recall_at_zero_fp": recall,
    }


def main() -> int:
    corpus_texts = {text for _, _, text in CORPUS}
    leaked = [probe for probe in BENIGN_CALIBRATION_PROBES if probe in corpus_texts]
    for text in KNOWN_FALSE_POSITIVES:
        if text in corpus_texts:
            leaked.append(text)
        if text in BENIGN_CALIBRATION_PROBES:
            print(f"ERROR: known false positive is also a calibration probe: {text}")
            return 1
    if leaked:
        print(f"ERROR: {len(leaked)} calibration probe(s) are also corpus samples:")
        for probe in leaked:
            print(f"  {probe}")
        return 1
    print(
        f"precondition ok: {len(BENIGN_CALIBRATION_PROBES)} probes and "
        f"{len(KNOWN_FALSE_POSITIVES)} registered false positives, "
        f"0 overlap with the {len(CORPUS)}-sample corpus"
    )

    v3 = _run("char n-grams on ALL tokens (v3 behaviour)", char_ngram_all_tokens=True)
    v4 = _run("char n-grams on NON-WORD tokens only (v4)", char_ngram_all_tokens=False)

    print("\n=== verdict ===")
    print(
        f"  zero-FP recall: {v3['recall_at_zero_fp']:.3f} -> {v4['recall_at_zero_fp']:.3f}  "
        f"(delta {v4['recall_at_zero_fp'] - v3['recall_at_zero_fp']:+.3f})"
    )
    print(f"  nuisance ceiling: {v3['ceiling']:.3f} -> {v4['ceiling']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
