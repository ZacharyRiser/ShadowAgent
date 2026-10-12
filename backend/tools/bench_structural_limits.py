#!/usr/bin/env python
"""Quantify what the bag-of-n-grams model structurally cannot reach.

Answers one question with data: **how much injection recall is unreachable
without an embedding layer, and would plain corpus growth buy it back?**

Method
------
1. Assert the probe set is disjoint from the training corpus. A probe that also
   exists in ``CORPUS`` measures memorisation, not generalisation.
2. Score every attack probe through the shipped model (ML) and through the
   production fused path (layer-one regex + ML).
3. For probes the production path misses, measure the three quantities that
   discriminate "needs training data" from "needs a different architecture":
   * **coverage** — the fraction of the text's features the model even has a
     weight for. Low coverage means the n-grams were never seen: a data fix is
     plausible, because training on them would create the missing weights.
   * **feature count** — a text that produced almost no representation is not a
     data problem at all; there was nothing to match on.
   * **function-word dominance** — the largest *positive* contribution coming
     from a function word means the model is reading sentence framing as
     evidence of intent.
4. Score the mention/use pairs on both halves, separating the pairs owned by the
   semantic layer from those owned by the DLP / tool-policy layers.

Read-only: it never writes the corpus, the probes or the model artifact.

Usage (run from ``backend/``)::

    python tools/bench_structural_limits.py
    python tools/bench_structural_limits.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

os.environ.setdefault("SHADOW_AGENT_SEMANTIC_MODE", "enforce")

from app import semantic  # noqa: E402
from app.semantic import (  # noqa: E402
    extract_features,
    feature_names,
    score_text,
    semantic_threshold,
)
from app.semantic_corpus import BENIGN_CALIBRATION_PROBES, CORPUS  # noqa: E402
from app.semantic_limit_probes import (  # noqa: E402
    MENTION_VS_USE_PAIRS,
    injection_probes,
    out_of_scope_pairs,
)
from security_engine import semantic_intent_check  # noqa: E402

_TOKEN_RE = re.compile(r"[0-9a-z\u00c0-\u024f\u0370-\u04ff]+")

# Coverage below this means most of the text's n-grams have no learned weight,
# so the score is being shrunk toward the out-of-domain prior rather than
# computed from evidence. Same floor the scorer uses for the trust ramp.
LOW_COVERAGE = 0.5
FEW_FEATURES = 10

# Function words across the languages the corpus covers. Their presence is
# framing, not intent; a probe whose strongest positive evidence is one of these
# is being scored on sentence shape.
STOPWORDS = frozenset(
    """
    a an and are as at be by do for from he her his i if in is it its me my no not
    of on or our so that the their them then there these they this to up us was we
    what when which who why will with you your
    aber alle allen aller als auch auf aus bei das dem den der des die ein eine
    einem einen einer er es für ich im in ist jede jeden mit nach nicht nur oder
    sein sind um und von vor war was wenn wie wir zu zum zur
    alors aussi avec aux ce ces cette comme dans de des du elle elles en est et
    il ils je la le les leur lui ma mais me mes moi ne nos notre nous ou par pas
    plus pour que quel quelle qui sa se ses son sont sur ta te tes toi ton tu un
    une vos votre vous
    al algo como con cual cuando de del el ella ellas ellos en es esta este esto
    la las lo los mas más me mi mis no nos o para pero por que se si sin su sus
    te tu tus un una unos y yo
    a ao aos as com da das de do dos e ela ele em eu isso isto mas na não nas no
    nos o os ou para pelo por qual que se sem seu seus sua suas um uma
    che chi ci con da dal dei del della di e è gli i il in io la le lei lo ma mi
    ne nei nel non o per più quale se si sono su tra un una uno
    а в все всё вы да для его если же и из к как не но о он она они от по с со
    так то ты у уж что чтобы это я
    """.split()
)


def _tokens(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    intersection = len(left & right)
    if not intersection:
        return 0.0
    return intersection / len(left | right)


def _is_function_like(feature: str) -> bool:
    if feature.startswith("z1:"):
        # A single CJK character carries almost no discriminative content on its
        # own; a longer run would also have produced z2/z3 features.
        return True
    if feature.startswith("w:"):
        return feature[2:] in STOPWORDS
    return False


def analyse(text: str, model, top_n: int) -> dict:
    """Feature-level explanation of one text's score."""
    features = extract_features(text)
    names: dict[int, str] = {}
    for name in feature_names(text):
        names.setdefault(semantic._stable_feature_hash(name), name)

    contributions: list[tuple[str, float]] = []
    matched = 0
    for bucket, value in features.items():
        weight = model.weights.get(bucket)
        if weight is None:
            continue
        matched += 1
        contributions.append((names.get(bucket, "#%d" % bucket), weight * value))
    contributions.sort(key=lambda item: abs(item[1]), reverse=True)

    positive = [item for item in contributions if item[1] > 0]
    top_positive = max(positive, key=lambda item: item[1]) if positive else ("", 0.0)
    coverage = matched / len(features) if features else 0.0
    return {
        "nonzero_features": len(features),
        "matched_features": matched,
        "coverage": round(coverage, 4),
        "top_features": contributions[:top_n],
        "top_positive_feature": top_positive[0],
        "top_positive_value": round(top_positive[1], 3),
        "function_word_driven": _is_function_like(top_positive[0]),
    }


def classify(row: dict) -> str:
    """Which explanation fits a missed probe."""
    if row["nonzero_features"] < FEW_FEATURES:
        return "almost_no_representation"
    if row["coverage"] < LOW_COVERAGE:
        return "mostly_unseen_ngrams"
    if row["function_word_driven"]:
        return "framing_dominates"
    return "represented_but_scored_benign"


def _nearest_injection(text: str, corpus_injections: list[str]) -> tuple[str, float]:
    tokens = _tokens(text)
    best_text, best_score = "", 0.0
    for candidate in corpus_injections:
        score = _jaccard(tokens, _tokens(candidate))
        if score > best_score:
            best_text, best_score = candidate, score
    return best_text, best_score


def _judge(text: str, threshold: float) -> dict:
    ml_score = score_text(text)
    fused = semantic_intent_check(text)
    return {
        "ml_score": round(ml_score, 4),
        "ml_blocked": ml_score >= threshold,
        "fused_blocked": not fused.allowed,
        "fused_reason": fused.reason,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--top-features", type=int, default=3)
    args = parser.parse_args(argv)

    model = semantic._load_model()
    if model is None:
        print("semantic model artifact is missing; nothing to measure", file=sys.stderr)
        return 2

    corpus_texts = {text for _label, _tag, text in CORPUS}
    benign_probe_texts = set(BENIGN_CALIBRATION_PROBES)
    corpus_injections = [text for label, _tag, text in CORPUS if label == "injection"]

    probes = injection_probes()
    overlaps = [
        text
        for _family, _language, text in probes
        if text in corpus_texts or text in benign_probe_texts
    ]

    threshold = semantic_threshold()
    families: dict[str, dict] = {}
    missed: list[dict] = []

    for family, language, text in probes:
        judgement = _judge(text, threshold)
        bucket = families.setdefault(family, {"n": 0, "ml_blocked": 0, "fused_blocked": 0})
        bucket["n"] += 1
        bucket["ml_blocked"] += int(judgement["ml_blocked"])
        bucket["fused_blocked"] += int(judgement["fused_blocked"])

        if judgement["fused_blocked"]:
            continue

        row = {"family": family, "language": language, "text": text, **judgement}
        row.update(analyse(text, model, args.top_features))
        nearest_text, nearest_score = _nearest_injection(text, corpus_injections)
        row["nearest_injection_jaccard"] = round(nearest_score, 3)
        row["nearest_injection"] = nearest_text[:120]
        row["classification"] = classify(row)
        missed.append(row)

    pair_rows = []
    for intent, language, benign, attack in MENTION_VS_USE_PAIRS:
        benign_judgement = _judge(benign, threshold)
        attack_judgement = _judge(attack, threshold)
        pair_rows.append(
            {
                "intent": intent,
                "language": language,
                "in_scope": intent == "prompt_injection",
                "benign_blocked": benign_judgement["fused_blocked"],
                "attack_blocked": attack_judgement["fused_blocked"],
                "separated": not benign_judgement["fused_blocked"] and attack_judgement["fused_blocked"],
                **{"benign_" + k: v for k, v in benign_judgement.items()},
                **{"attack_" + k: v for k, v in attack_judgement.items()},
            }
        )

    in_scope_pairs = [row for row in pair_rows if row["in_scope"]]
    other_pairs = [row for row in pair_rows if not row["in_scope"]]
    in_scope_texts = {
        text
        for _intent, _language, benign, attack in MENTION_VS_USE_PAIRS
        if _intent == "prompt_injection"
        for text in (benign, attack)
    }
    pair_overlaps = sorted(in_scope_texts & (corpus_texts | benign_probe_texts))

    classification_counts: dict[str, int] = {}
    for row in missed:
        classification_counts[row["classification"]] = classification_counts.get(row["classification"], 0) + 1

    language_counts: dict[str, int] = {}
    for row in missed:
        language_counts[row["language"]] = language_counts.get(row["language"], 0) + 1

    report = {
        "runner": "bench_structural_limits",
        "model_version": model.version,
        "threshold": round(threshold, 4),
        "corpus_size": len(CORPUS),
        "probe_count": len(probes),
        "probe_corpus_overlap": len(overlaps),
        "pair_corpus_overlap": len(pair_overlaps),
        "families": families,
        "missed_count": len(missed),
        "missed_by_classification": classification_counts,
        "missed_by_language": language_counts,
        "missed": missed,
        "mention_vs_use_pairs": pair_rows,
        "out_of_scope_intents": sorted({intent for intent, *_ in out_of_scope_pairs()}),
    }

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    print("model v%s  threshold=%.4f  corpus=%d  probes=%d" % (model.version, threshold, len(CORPUS), len(probes)))
    print("overlap with corpus/benign probes: %d (must be 0)" % (len(overlaps) + len(pair_overlaps)))
    for text in overlaps + pair_overlaps:
        print("  ! probe is also training/calibration material: %r" % text[:90])
    print()

    header = "%-22s %4s %10s %13s %7s %7s" % ("family", "n", "ml_block", "fused_block", "missed", "recall")
    print(header)
    print("-" * len(header))
    for family in sorted(families):
        row = families[family]
        print(
            "%-22s %4d %10d %13d %7d %6.1f%%"
            % (
                family,
                row["n"],
                row["ml_blocked"],
                row["fused_blocked"],
                row["n"] - row["fused_blocked"],
                100.0 * row["fused_blocked"] / row["n"],
            )
        )
    print()

    print("== probes the production path lets through ==")
    for row in missed:
        print(
            "  [%s/%s] score=%.4f class=%s coverage=%.2f (%d/%d) nn=%.3f"
            % (
                row["family"],
                row["language"],
                row["ml_score"],
                row["classification"],
                row["coverage"],
                row["matched_features"],
                row["nonzero_features"],
                row["nearest_injection_jaccard"],
            )
        )
        print("      %s" % row["text"][:100])
        print(
            "      top-positive: %s %+.3f (function-like=%s)"
            % (row["top_positive_feature"], row["top_positive_value"], row["function_word_driven"])
        )
        for name, value in row["top_features"]:
            print("      | %-26s %+.3f" % (name, value))
    if not missed:
        print("  (none)")
    print()

    print("== mention versus use ==")
    for row in pair_rows:
        tag = "in-scope" if row["in_scope"] else "other-layer"
        print(
            "  %-11s benign=%.4f attack=%.4f separated=%s"
            % (tag, row["benign_ml_score"], row["attack_ml_score"], row["separated"])
        )
    print()

    total = len(probes)
    unreachable = len(missed)
    print("== verdict inputs ==")
    print(
        "unreachable by the production path: %d/%d = %.1f%% of the injection probes"
        % (unreachable, total, 100.0 * unreachable / total if total else 0.0)
    )
    for name in ("almost_no_representation", "mostly_unseen_ngrams", "framing_dominates", "represented_but_scored_benign"):
        count = classification_counts.get(name, 0)
        if count:
            print("    %-30s %d" % (name, count))
    print("  missed by language: %s" % ", ".join("%s=%d" % item for item in sorted(language_counts.items())))
    print(
        "  in-scope mention/use pairs separated: %d/%d"
        % (sum(1 for row in in_scope_pairs if row["separated"]), len(in_scope_pairs))
    )
    print(
        "  false positives inside the mention/use family: %d"
        % sum(1 for row in pair_rows if row["benign_blocked"])
    )
    print(
        "  out-of-scope pairs (other layers own the attack half): %d %s"
        % (len(other_pairs), [row["intent"] for row in other_pairs])
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
