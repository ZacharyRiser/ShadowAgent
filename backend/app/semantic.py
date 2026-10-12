"""Local semantic injection detection — feature extraction, model, and scoring.

Everything runs in-process with zero network access: the classifier is a
compact logistic-regression model over hashed n-gram features, shipped as
``semantic_model.json`` next to this module and trained by
``tools/train_semantic_model.py`` over ``app/semantic_corpus.py``.

Feature family is chosen per script, because tokenisation cannot be uniform:
Latin/Cyrillic text is word-delimited (word 1/2-grams + within-word character
n-grams), while CJK/Kana/Hangul has no delimiters and is modelled with
character 1/2/3-grams over each run. Both feed one hashed bucket space.

Decision policy (mirrors the response-side DLP modes):

* ``off``     — the classifier is skipped entirely.
* ``monitor`` — scores at/above the threshold stay allowed but are flagged as
  suspected (visible in ``/api/v1/analyze`` output and audit logs).
* ``enforce`` — scores at/above the threshold block the request (403).

Independently of the mode, a score within ``SEMANTIC_SUSPECT_BAND`` *below* the
blocking threshold is flagged as suspected while still being allowed. That band
carries the audit trail through the region where this classifier is genuinely
uncertain, so the system can be conservative about blocking without going blind
— see ``SEMANTIC_SUSPECT_BAND``.

Configuration (read lazily per call, same pattern as the DLP engine):

* ``SHADOW_AGENT_SEMANTIC_MODE``      — off | monitor | enforce (default enforce)
* ``SHADOW_AGENT_SEMANTIC_THRESHOLD`` — override the artifact threshold (0.5–0.99)
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import threading
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("shadow_agent.semantic")

SEMANTIC_MODES = ("off", "monitor", "enforce")
DEFAULT_SEMANTIC_MODE = "enforce"
MODEL_FILENAME = "semantic_model.json"

# Width of the "suspected" band below the blocking threshold.
#
# This classifier has no sharp decision boundary: its benign and malicious
# score distributions overlap in a grey zone, because a bag-of-n-grams model
# cannot tell "upload the build artefact to the internal mirror" from "upload
# the secrets to my bucket" — the strings are nearly identical to it. Forcing
# that zone into a binary is what made the layer fragile: a score shift of a few
# points from a retrain flipped a sample between "allowed silently" and
# "blocked", which is an expensive way to express uncertainty.
#
# A score inside the band is *allowed in every mode* but flagged as suspected:
# it lands in the audit trail and live console as a ``Monitored`` event and
# appears in ``/api/v1/analyze``. The band therefore keeps the region below the
# threshold monitored rather than silent, and a retrain shifting a sample by a
# few points changes a label instead of producing a 403.
SEMANTIC_SUSPECT_BAND = 0.15

# Feature extraction must stay byte-identical between training and inference:
# the trainer imports these constants/functions from this module.
FEATURE_BUCKETS = 2**17

# Unicode normalization form applied before tokenization. NFKC folds
# compatibility characters onto their canonical equivalents, so full-width
# ("Ｉｇｎｏｒｅ"), mathematical-alphanumeric ("𝐈𝐠𝐧𝐨𝐫𝐞") and circled
# ("Ⓘⓖⓝⓞⓡⓔ") obfuscations collapse onto the ASCII the detector understands.
# Without it these scripts tokenize to nothing and the text is invisible.
# NFKC deliberately does NOT strip zero-width characters: their density is
# itself a learned attack signal that the corpus relies on.
UNICODE_NORMALIZATION = "NFKC"

# Latin/Cyrillic/Thai script: word-level n-grams (spaces delimit tokens) plus
# within-word character n-grams for morphology and leetspeak/homoglyph noise.
WORD_NGRAM_SIZES = (1, 2)
CHAR_NGRAM_SIZES = (3, 4)
MAX_TOKEN_CHARS = 24

# Within-word character n-grams exist for one reason: to recover signal from
# tokens that are not ordinary words — tokens carrying digits ("1gn0re"),
# non-ASCII characters (mixed-script homoglyphs such as "disregаrd" with a
# Cyrillic "а"), or otherwise non-letter content. A plain lowercase ASCII word
# does not need them: the word and word-bigram features already carry its
# meaning.
#
# Emitting them for ordinary words as well is what made this layer's scores
# fragile. In a corpus of a few hundred samples a generic English trigram such
# as ``ere`` (from where/were/here/there) picks up positive weight by chance,
# so *any* English text — SQL, prose, code — rides it toward the threshold.
# Measured on the shipped v3 model: ``SELECT id, name FROM users WHERE
# created_at ...`` scored 0.70 with the character family contributing +1.96 of
# a +0.84 logit, and the worst benign calibration probe reached 0.95. That is
# why the old threshold had to sit at 0.85 (a floor set by avoiding false
# positives, not by in-corpus separation) and why dozens of injections crowded
# the band right next to it: the noise inflates everything, so the margin
# between benign and malicious collapses.
#
# Gating the family to non-word tokens drops the worst benign probe to 0.73 and
# *raises* recall: held-out encoding-obfuscation recall 6/7 -> 7/7, overall
# 87.2% -> 88% at the zero-false-positive operating point. Less feature noise
# means the word weights generalise better, so this is an improvement on both
# axes rather than a trade. Held-out probes confirm the direction: a novel
# mixed-script homoglyph moves 0.25 -> 0.54 and a leetspeak payload 0.42 ->
# 0.68 with this gating.
#
# Known residual: separators *inside* ASCII words ("instruc.tions") no longer
# get character n-grams, so a novel such split is still missed. That was true
# of v3 as well (it scored such a probe 0.17 — the corpus copy is only caught
# because it is memorised); closing it needs an explicit separator-collapse
# pass in the signature layer, which is tracked in the benchmark roadmap.
_PLAIN_WORD_RE = re.compile(r"[a-z]+")

# CJK/Kana/Hangul: no word delimiters, so word tokens are meaningless — a whole
# sentence collapses into a single token whose n-grams barely overlap any other
# sentence. These scripts are instead modeled with character n-grams over each
# run, where 2-grams approximate words ("忽略", "指令") and 3-grams approximate
# common phrases. This is the fix for the Chinese recall gap.
CJK_NGRAM_SIZES = (1, 2, 3)
MAX_CJK_RUN_CHARS = 512
MAX_CJK_WHOLE_RUN_CHARS = 6

MAX_SCAN_CHARS = 5000

# One alternation, two very different feature families: ASCII-ish word runs are
# tokenized on whitespace boundaries, CJK runs are tokenized per character.
_WORD_CLASS = r"0-9a-z\u00c0-\u024f\u0370-\u04ff\u0e00-\u0e7f\u1e00-\u1eff"
_CJK_CLASS = r"\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uac00-\ud7af"
_SEGMENT_RE = re.compile(rf"[{_WORD_CLASS}]+|[{_CJK_CLASS}]+")
_CJK_RUN_RE = re.compile(rf"[{_CJK_CLASS}]+")
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class SemanticModel:
    """Sparse logistic-regression model over hashed n-gram features."""

    bias: float
    weights: dict[int, float]
    threshold: float
    version: int
    trained_at: str
    feature_buckets: int
    train_metrics: dict[str, Any]
    config: dict[str, Any]


_MODEL_LOCK = threading.Lock()
_MODEL_CACHE: SemanticModel | None = None
_MODEL_LOADED = False


def _model_path() -> Path:
    return Path(__file__).resolve().parent / MODEL_FILENAME


def _load_model() -> SemanticModel | None:
    """Load the shipped model artifact once; degrade to None when unusable."""

    global _MODEL_CACHE, _MODEL_LOADED

    if _MODEL_LOADED:
        return _MODEL_CACHE

    with _MODEL_LOCK:
        if _MODEL_LOADED:
            return _MODEL_CACHE

        path = _model_path()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            indices = raw["feature_indices"]
            values = raw["feature_weights"]
            if len(indices) != len(values):
                raise ValueError("feature index/weight length mismatch")
            buckets = int(raw["config"]["feature_buckets"])
            if buckets != FEATURE_BUCKETS:
                raise ValueError(
                    f"model expects {buckets} buckets, runtime uses {FEATURE_BUCKETS}"
                )
            _MODEL_CACHE = SemanticModel(
                bias=float(raw["bias"]),
                weights={
                    int(index): float(weight)
                    for index, weight in zip(indices, values)
                    if float(weight) != 0.0
                },
                threshold=float(raw["threshold"]),
                version=int(raw.get("version", 1)),
                trained_at=str(raw.get("trained_at", "")),
                feature_buckets=buckets,
                train_metrics=dict(raw.get("train_metrics", {})),
                config=dict(raw.get("config", {})),
            )
        except FileNotFoundError:
            logger.warning(
                "Semantic model artifact %s not found — semantic detection disabled. "
                "Run tools/train_semantic_model.py to regenerate it.",
                path,
            )
            _MODEL_CACHE = None
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            logger.warning(
                "Semantic model artifact %s is invalid (%s) — semantic detection disabled.",
                path,
                error,
            )
            _MODEL_CACHE = None

        _MODEL_LOADED = True
        return _MODEL_CACHE


def _stable_feature_hash(feature: str) -> int:
    """Deterministic across processes (unlike built-in hash for str)."""

    digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % FEATURE_BUCKETS


def _add_cjk_features(names: set[str], run: str) -> None:
    """Character n-grams for one CJK/Kana/Hangul run.

    Runs are capped independently of ``MAX_TOKEN_CHARS``: the word-token cap
    exists to bound hash cost per Latin token, whereas a Chinese sentence is a
    single "token" and truncating it there would discard most of its features.
    """

    run = run[:MAX_CJK_RUN_CHARS]
    if len(run) <= MAX_CJK_WHOLE_RUN_CHARS:
        # Short runs ("忽略指令") are cheap and highly discriminative.
        names.add(f"zw:{run}")
    for size in CJK_NGRAM_SIZES:
        for start in range(len(run) - size + 1):
            names.add(f"z{size}:{run[start:start + size]}")


def _is_plain_word(token: str) -> bool:
    """True when ``token`` is a plain lowercase ASCII letter run.

    Those tokens are represented by the word / word-bigram features; emitting
    their internal character n-grams only adds the spurious evidence described
    at ``_PLAIN_WORD_RE``. Everything else — a digit-bearing leetspeak fragment,
    a mixed-script homoglyph, anything the segmenter kept that is not letters —
    *is* given character n-grams, which is the entire point of that family.
    """

    return _PLAIN_WORD_RE.fullmatch(token) is not None


def feature_names(text: str) -> set[str]:
    """Unhashed feature names generated for ``text``.

    Split out of ``extract_features`` so diagnostics can attribute a hashed
    bucket back to the n-gram that produced it: the bucket function is a
    blake2b modulus, so a bucket cannot be inverted or guessed. This is the
    single source of truth for feature generation — ``extract_features`` calls
    it, and so does the trainer.

    Latin-script words contribute unigrams/bigrams; non-word tokens (see
    ``_is_plain_word``) additionally contribute within-word character n-grams
    for obfuscation robustness. CJK runs contribute character 1/2/3-grams
    spanning the whole run. Both feed the same hashed bucket space, so a
    mixed-language text gets both views. 

    Text is NFKC-normalized first (see ``UNICODE_NORMALIZATION``) so that
    compatibility-character obfuscation cannot hide a payload from the
    tokenizer. Measured over the shipped corpus this alters the feature vector
    of exactly one sample (the full-width obfuscation attack) and leaves every
    other sample byte-identical, so it adds coverage without shifting behaviour.
    """

    normalized = _WHITESPACE_RE.sub(
        " ", unicodedata.normalize(UNICODE_NORMALIZATION, text).lower()
    )[:MAX_SCAN_CHARS]
    if not normalized:
        return set()

    names: set[str] = set()
    words: list[str] = []
    for segment in _SEGMENT_RE.findall(normalized):
        if _CJK_RUN_RE.fullmatch(segment):
            _add_cjk_features(names, segment)
            continue
        capped = segment[:MAX_TOKEN_CHARS]
        words.append(capped)
        names.add(f"w:{capped}")
        if _is_plain_word(capped):
            continue
        for size in CHAR_NGRAM_SIZES:
            for start in range(len(capped) - size + 1):
                names.add(f"c{size}:{capped[start:start + size]}")

    # Word bigrams cross word boundaries only (CJK runs are excluded: adjacent
    # CJK characters are already covered by the z2/z3 features above).
    for size in WORD_NGRAM_SIZES:
        if size < 2:
            continue
        for start in range(len(words) - size + 1):
            names.add("b:" + "|".join(words[start:start + size]))

    return names


def extract_features(text: str) -> dict[int, float]:
    """Hashed, L2-normalized presence vector over ``feature_names(text)``.

    Shared verbatim by the trainer and the runtime scorer, so a change here
    changes the meaning of every stored weight and requires a retrain.
    """

    names = feature_names(text)
    if not names:
        return {}

    scale = 1.0 / math.sqrt(len(names))
    return {_stable_feature_hash(name): scale for name in names}


def _sigmoid(value: float) -> float:
    if value >= 0:
        exponent = math.exp(-value)
        return 1.0 / (1.0 + exponent)
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)


# Logit used as the prior for out-of-vocabulary text. Unseen traffic is far
# more likely to be benign than an attack, so a fully unmatched text scores
# ~0.2 instead of drifting toward sigmoid(bias).
OOD_PRIOR_LOGIT = -1.2

# Coverage at which the raw logit is trusted in full (see ``score_features``).
# Below it the score ramps linearly down to ``OOD_PRIOR_LOGIT`` at 0% coverage.
#
# Why a floor instead of the original ``coverage * logit`` ramp: a linear ramp
# taxed genuinely out-of-domain text twice — once for an unfamiliar vocabulary,
# once for the ramp — and on the held-out split moving to a floor raised Chinese
# recall from 50% to 86% with zero new false positives. Text that really is from
# another domain (other languages, SQL, code, LaTeX) still lands well under the
# floor and gets shrunk.
#
# Correction (measured, roadmap item 8): the original rationale for the floor
# claimed CJK character n-grams have "naturally lower" coverage than Latin word
# features, so a uniform floor implicitly penalised Chinese. That is **not**
# supported by the data — in-corpus median coverage is 1.000 for both zh and en,
# and on the held-out split the *lowest*-coverage injections are English
# (zh min 0.500 vs en min 0.263), not Chinese. Normalising coverage per script
# was evaluated and rejected: it drops 24 held-out injection detections to buy a
# 0.12 improvement in the worst-probe margin. The floor is kept as a uniform
# value; it discriminates on content-level out-of-domain-ness, not on language.
COVERAGE_TRUST_FLOOR = 0.5


def score_features(
    weights: dict[int, float],
    bias: float,
    features: dict[int, float],
) -> float:
    """Coverage-aware logistic score.

    When most of a text's features were never seen in training (out-of-corpus
    phrasing, another language), the raw logit is mostly noise: it is shrunk
    toward the benign-leaning prior proportionally to the unseen fraction.
    In-corpus texts keep their full score, so training-separation is preserved.
    """

    if not features:
        return _sigmoid(bias)

    logit = bias
    matched = 0
    for bucket, value in features.items():
        weight = weights.get(bucket)
        if weight is not None:
            logit += weight * value
            matched += 1

    coverage = matched / len(features)
    trust = min(1.0, coverage / COVERAGE_TRUST_FLOOR)
    adjusted = trust * logit + (1.0 - trust) * OOD_PRIOR_LOGIT
    return _sigmoid(adjusted)


def score_text(text: str) -> float:
    """Injection probability in [0, 1]; 0.0 when no model or empty input."""

    model = _load_model()
    if model is None or not text or not text.strip():
        return 0.0

    features = extract_features(text)
    if not features:
        return 0.0

    return score_features(model.weights, model.bias, features)


def semantic_mode() -> str:
    """Current semantic-detection mode (lazy env read, validated)."""

    raw = os.getenv("SHADOW_AGENT_SEMANTIC_MODE", "").strip().lower()
    if raw in SEMANTIC_MODES:
        return raw
    if raw:
        logger.warning(
            "Invalid SHADOW_AGENT_SEMANTIC_MODE %r — falling back to %r.",
            raw,
            DEFAULT_SEMANTIC_MODE,
        )
    return DEFAULT_SEMANTIC_MODE


def semantic_threshold() -> float:
    """Effective blocking threshold: env override, else the artifact value."""

    raw = os.getenv("SHADOW_AGENT_SEMANTIC_THRESHOLD", "").strip()
    if raw:
        try:
            override = float(raw)
        except ValueError:
            logger.warning("Invalid SHADOW_AGENT_SEMANTIC_THRESHOLD %r — ignored.", raw)
        else:
            if 0.5 <= override <= 0.99:
                return override
            logger.warning(
                "SHADOW_AGENT_SEMANTIC_THRESHOLD %r outside 0.5–0.99 — ignored.", raw
            )

    model = _load_model()
    if model is not None and 0.5 <= model.threshold <= 0.99:
        return model.threshold
    return 0.85


def semantic_suspect_floor() -> float:
    """Score at/above which text is *flagged* as suspected without blocking.

    Always ``SEMANTIC_SUSPECT_BAND`` below the effective blocking threshold, so
    retuning the threshold (env or artifact) moves the band with it and the band
    can never cross above the block decision.
    """

    return max(0.0, semantic_threshold() - SEMANTIC_SUSPECT_BAND)


def semantic_ml_check(text: str) -> dict[str, Any] | None:
    """Score ``text`` with the local classifier.

    Returns ``None`` when the layer is disabled or unavailable. Otherwise a
    payload consumed by ``security_engine.semantic_intent_check``:

    * ``block``        — True when the score is at/above the threshold in enforce mode
    * ``suspected``    — True when the score is at/above ``semantic_suspect_floor``
      (i.e. either blocking or inside the grey band)
    * ``score``        — calibrated injection probability
    * ``suspect_floor``— the band floor actually applied
    * ``mode`` / ``threshold`` / ``model_version`` — decision context
    """

    mode = semantic_mode()
    if mode == "off":
        return None

    model = _load_model()
    if model is None or not text or not text.strip():
        return None

    score = score_text(text)
    threshold = semantic_threshold()
    suspect_floor = semantic_suspect_floor()
    at_threshold = score >= threshold

    # Observe the *raw* calibrated score, not the resulting decision.
    #
    # ``semantic_intent_check`` returns the layer-1 decision verbatim when the
    # score sits below the suspicion floor, so the score never reaches the audit
    # layer for ordinary traffic. Recording it here is the only place the
    # threshold-proximity of benign traffic is observable — and that proximity is
    # what tells an operator whether the threshold still has headroom.
    #
    # Imported lazily so the module stays importable without the web/metrics
    # layer (``tools/train_semantic_model.py`` imports this module directly).
    from app.metrics import record_semantic_score

    record_semantic_score(layer="semantic_ml", score=score)

    return {
        "block": mode == "enforce" and at_threshold,
        "suspected": score >= suspect_floor,
        "score": round(score, 4),
        "mode": mode,
        "threshold": round(threshold, 4),
        "suspect_floor": round(suspect_floor, 4),
        "model_version": model.version,
    }


def semantic_status() -> dict[str, Any]:
    """Runtime status for the admin console and launch checks."""

    model = _load_model()
    return {
        "mode": semantic_mode(),
        "available_modes": list(SEMANTIC_MODES),
        "threshold": semantic_threshold(),
        "suspect_floor": semantic_suspect_floor(),
        "suspect_band": SEMANTIC_SUSPECT_BAND,
        "model_loaded": model is not None,
        "model_version": model.version if model else None,
        "trained_at": model.trained_at if model else None,
        "train_metrics": model.train_metrics if model else None,
        "model_config": model.config if model else None,
        "max_scan_chars": MAX_SCAN_CHARS,
    }


def reset_model_cache() -> None:
    """Test hook: force the next call to reload the artifact from disk."""

    global _MODEL_CACHE, _MODEL_LOADED

    with _MODEL_LOCK:
        _MODEL_CACHE = None
        _MODEL_LOADED = False
