"""Per-language detection matrix: the guard against silently losing a language.

Motivation is a measured failure, not a hypothetical. A previous round added 22
Latin-script European injection samples (German / French / Portuguese / Spanish
/ Italian) and it worked — held-out recall rose 0.734 -> 0.768. But the same
single-variable sweep also showed that adding *Russian* samples next to those
broke the Russian samples that were already there (3/3 -> 1/3): the "forget" /
"ignore" stems of Russian, German and French compete for the same hash buckets,
so a language with few samples is fragile to additions made in a *different*
language.

Word-level unigrams do not share stems, so this is structural, not a bug to fix
by tuning. The mitigation is procedural: before shipping any corpus addition,
re-train and re-check the per-language pass rate, and confirm that no language
that was passing before slipped below the threshold.

This tool trains on the current corpus + an optional block of extra samples and
prints, per language, how many of the corpus injections still score above the
threshold. It is deliberately read-only — feed it candidate additions to test
them; it never writes the corpus or the model.

Usage (from ``backend/``):
    python tools/ablate_language_coverage.py
    python tools/ablate_language_coverage.py --extra path/to/candidates.txt
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tools.train_semantic_model as trainer  # noqa: E402
from app.semantic import extract_features, score_features  # noqa: E402
from app.semantic_corpus import CORPUS  # noqa: E402

# Character ranges that identify the language of a sample well enough for a
# coverage matrix. Ordered by specificity: diacritics first, CJK ranges last.
_LANGUAGE_MARKERS: tuple[tuple[str, str], ...] = (
    ("ru", "\u0400-\u04ff"),
    ("ko", "\uac00-\ud7af"),
    ("ja", "\u3040-\u30ff"),
    ("zh", "\u4e00-\u9fff"),
)
_DIACRITIC_MARKERS: tuple[tuple[str, str], ...] = (
    ("de", "äöüß"),
    ("fr", "àâçéèêëîïôûùÿœæ"),
    ("pt", "ãõçáâàéêíóôú"),
    ("es", "áéíóúñ¿¡"),
    ("it", "àèéìòù"),
)


def language_of(text: str) -> str:
    """Rough language tag for a sample; good enough to group a corpus."""

    for tag, char_range in _LANGUAGE_MARKERS:
        if any(char_range[0] <= ch <= char_range[-1] for ch in text):
            return tag
    lowered = text.lower()
    for tag, chars in _DIACRITIC_MARKERS:
        if any(ch in lowered for ch in chars):
            return tag
    return "en"


def _split_with_extra(
    extra: list[str],
) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    """Replicate ``trainer.stratified_split`` with extra samples appended.

    Kept local rather than monkey-patching the module global so the split is
    reproducible and the real ``CORPUS`` is never mutated.
    """

    buckets: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for sample in CORPUS:
        buckets.setdefault((sample[0], sample[1]), []).append(sample)
    for text in extra:
        buckets.setdefault(("injection", "translation_paraphrase"), []).append(
            ("injection", "translation_paraphrase", text)
        )

    train: list[tuple[str, str, str]] = []
    heldout: list[tuple[str, str, str]] = []
    for key in sorted(buckets):
        group = list(buckets[key])
        rng = random.Random(f"{trainer.SPLIT_SEED}:{key[0]}:{key[1]}")
        rng.shuffle(group)
        holdout_count = (
            max(1, round(len(group) * trainer.HOLDOUT_FRACTION)) if len(group) >= 2 else 0
        )
        heldout.extend(group[:holdout_count])
        train.extend(group[holdout_count:])
    return train, heldout


def _report(extra: list[str], label: str) -> dict[str, tuple[int, int]]:
    train, _ = _split_with_extra(extra)
    weights, bias, _ = trainer._train(train, epochs=100, lr0=0.5, l2_lambda=1e-6)
    calibration = trainer._calibrate_threshold(weights, bias)
    threshold = calibration["threshold"]

    groups: dict[str, list[str]] = {}
    for sample_label, _tag, text in CORPUS:
        if sample_label == "injection":
            groups.setdefault(language_of(text), []).append(text)

    print(
        f"\n=== {label} ===\n"
        f"  corpus {len(CORPUS) + len(extra)}  threshold {threshold:.4f}  "
        f"ceiling {calibration['ceiling']:.4f}"
    )
    result: dict[str, tuple[int, int]] = {}
    for language in sorted(groups):
        scores = [
            score_features(weights, bias, extract_features(text))
            for text in groups[language]
        ]
        passed = sum(1 for score in scores if score >= threshold)
        result[language] = (passed, len(scores))
        # Note: "below threshold" here means a corpus sample the shipped model
        # does not block. Some of those are the pre-existing split-luck misses
        # (the corpus is largely train-split, so this is not a held-out report);
        # what matters is the *change* between the baseline and candidate runs,
        # which the verdict section reports.
        flag = "" if passed == len(scores) else "   <-- below threshold"
        print(f"   {language:3s} {passed}/{len(scores)} blocked{flag}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--extra",
        type=Path,
        default=None,
        help="optional text file, one candidate injection per line",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="print only the per-language matrix",
    )
    args = parser.parse_args()

    extra: list[str] = []
    if args.extra is not None:
        extra = [
            line.strip()
            for line in args.extra.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    baseline = _report([], "baseline (current corpus)")
    if not extra:
        return 0

    candidate = _report(extra, f"with {len(extra)} addition(s) from {args.extra}")

    print("\n=== verdict ===")
    regressions = 0
    for language in sorted(baseline):
        before, total = baseline[language]
        after = candidate.get(language, (0, total))[0]
        if after < before:
            regressions += 1
            print(f"  REGRESSION {language}: {before}/{total} -> {after}/{total}")
    if regressions:
        print(
            f"  {regressions} language(s) lost coverage — do NOT ship these additions "
            "without reworking them."
        )
        return 1
    if not args.quiet:
        print("  no language regressed; additions are safe on this matrix")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
