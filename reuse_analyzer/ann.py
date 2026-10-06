"""Small offline ANN for an auxiliary, synthetic-data password pattern estimate.

The model only runs on transient structural features. It never persists or transmits
passwords. The existing explainable strength score remains the authoritative score.
"""
from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path

MODEL_PATH = Path(__file__).with_name("data") / "ann_strength_model.json"
FEATURES = (
    "length", "pool_size", "lower_ratio", "upper_ratio", "digit_ratio",
    "symbol_ratio", "unique_ratio", "repeat_ratio", "sequence_ratio",
    "alpha_ratio", "digit_run", "symbol_run",
)
LABELS = ("Weak", "Fair", "Strong")
CLASS_SCORES = (20, 55, 88)


def feature_vector(password: str) -> list[float]:
    """Convert a password to bounded shape features; raw text is not retained."""
    if not password:
        return [0.0] * len(FEATURES)
    n = len(password)
    lower = sum(c.islower() for c in password)
    upper = sum(c.isupper() for c in password)
    digits = sum(c.isdigit() for c in password)
    symbols = n - lower - upper - digits
    classes = sum(bool(x) for x in (lower, upper, digits, symbols))
    pool = (26 if lower else 0) + (26 if upper else 0) + (10 if digits else 0) + (33 if symbols else 0)
    repeats = sum(password[i] == password[i - 1] for i in range(1, n))
    sequences = sum(
        password[i].isalnum() and password[i - 1].isalnum()
        and abs(ord(password[i].lower()) - ord(password[i - 1].lower())) == 1
        for i in range(1, n)
    )
    digit_run = max((len(x) for x in re.findall(r"\d+", password)), default=0)
    symbol_run = max((len(x) for x in re.findall(r"[^A-Za-z0-9]+", password)), default=0)
    return [
        min(n, 32) / 32, pool / 95, lower / n, upper / n, digits / n, symbols / n,
        len(set(password)) / n, repeats / max(n - 1, 1), sequences / max(n - 1, 1),
        (lower + upper) / n, min(digit_run, 12) / 12, min(symbol_run, 12) / 12,
    ]


def _sigmoid(value: float) -> float:
    value = max(-30.0, min(30.0, value))
    return 1.0 / (1.0 + math.exp(-value))


@lru_cache(maxsize=1)
def _model() -> dict | None:
    try:
        with MODEL_PATH.open(encoding="utf-8") as handle:
            model = json.load(handle)
        if model.get("feature_names") != list(FEATURES) or model.get("labels") != list(LABELS):
            return None
        if len(model["hidden_weights"]) != len(model["hidden_bias"]) or len(model["output_weights"]) != 3:
            return None
        return model
    except (OSError, ValueError, KeyError, TypeError):
        return None


def estimate(password: str) -> dict | None:
    """Return ANN class probabilities and its auxiliary 0-100 score, when trained."""
    model = _model()
    if model is None:
        return None
    x = feature_vector(password)
    hidden = [_sigmoid(sum(w * v for w, v in zip(weights, x)) + bias)
              for weights, bias in zip(model["hidden_weights"], model["hidden_bias"])]
    logits = [sum(w * v for w, v in zip(weights, hidden)) + bias
              for weights, bias in zip(model["output_weights"], model["output_bias"])]
    peak = max(logits)
    exps = [math.exp(max(-30.0, min(30.0, value - peak))) for value in logits]
    total = sum(exps)
    probabilities = [value / total for value in exps]
    index = max(range(3), key=probabilities.__getitem__)
    score = round(sum(p * s for p, s in zip(probabilities, CLASS_SCORES)))
    return {"score": score, "label": LABELS[index], "confidence": round(probabilities[index] * 100),
            "classes": {label: round(probability * 100) for label, probability in zip(LABELS, probabilities)},
            "kind": "synthetic-pattern ANN"}
