"""Train the auxiliary strength-pattern ANN on generated examples (stdlib only).

Run with ``python -m reuse_analyzer.train_ann``. The CSV contains only numeric
features and synthetic class labels; generated password strings are never written.
"""
from __future__ import annotations

import csv
import json
import math
import random
from pathlib import Path

from .ann import FEATURES, LABELS, feature_vector

DATA_DIR = Path(__file__).with_name("data")
DATASET_PATH = DATA_DIR / "ann_strength_synthetic.csv"
MODEL_PATH = DATA_DIR / "ann_strength_model.json"
WORDS = ("amber", "birch", "cobalt", "dawn", "ember", "frost", "grove", "harbor",
         "indigo", "juniper", "kestrel", "lantern", "maple", "nectar", "orbit", "pebble",
         "quartz", "river", "silver", "timber", "umber", "violet", "willow", "xenon", "yellow", "zinc")


def examples(count_per_class: int = 700, seed: int = 271828) -> list[tuple[list[float], int]]:
    rng = random.Random(seed)
    rows: list[tuple[list[float], int]] = []
    for label in range(3):
        for _ in range(count_per_class):
            if label == 0:  # weak patterns: short, repeated, sequential, or common-like
                bases = ("password", "welcome", "qwerty", "summer", "letmein", "dragon", "monkey")
                base = rng.choice(bases)
                style = rng.randrange(4)
                if style == 0:
                    password = base + str(rng.randrange(100))
                elif style == 1:
                    password = base.capitalize() + str(rng.randrange(10, 100)) + "!"
                elif style == 2:
                    password = rng.choice("abc123") * rng.randint(4, 10)
                else:
                    password = rng.choice(("123", "1234", "abcd", "qwerty")) + str(rng.randrange(10))
            elif label == 1:  # fair patterns: a single word with some complexity
                word = rng.choice(WORDS).capitalize()
                password = word + str(rng.randrange(10, 10000)) + rng.choice(("!", "#", "@", "?"))
                if rng.random() < .35:
                    password = password + rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            else:  # strong shapes: long random strings or multiple unrelated words
                if rng.random() < .5:
                    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*"
                    password = "".join(rng.choice(alphabet) for _ in range(rng.randint(16, 26)))
                else:
                    chosen = rng.sample(WORDS, 4)
                    password = "-".join(chosen).capitalize() + str(rng.randrange(10, 100))
            rows.append((feature_vector(password), label))
    rng.shuffle(rows)
    return rows


def sigmoid(value: float) -> float:
    value = max(-30.0, min(30.0, value))
    return 1.0 / (1.0 + math.exp(-value))


def softmax(logits: list[float]) -> list[float]:
    peak = max(logits)
    exps = [math.exp(max(-30.0, value - peak)) for value in logits]
    total = sum(exps)
    return [value / total for value in exps]


def train(seed: int = 314159, count_per_class: int = 700, epochs: int = 22,
          hidden_size: int = 12, learning_rate: float = .08) -> dict:
    rng = random.Random(seed)
    rows = examples(count_per_class)
    # Stratified split. This verifies that each generated pattern class is present
    # in both training and validation sets.
    by_class = [[row for row in rows if row[1] == label] for label in range(3)]
    train_rows, valid_rows = [], []
    for group in by_class:
        cut = int(len(group) * .8)
        train_rows.extend(group[:cut])
        valid_rows.extend(group[cut:])
    rng.shuffle(train_rows)

    n_features = len(FEATURES)
    hw = [[rng.uniform(-.35, .35) for _ in range(n_features)] for _ in range(hidden_size)]
    hb = [0.0] * hidden_size
    ow = [[rng.uniform(-.35, .35) for _ in range(hidden_size)] for _ in range(3)]
    ob = [0.0] * 3

    for _epoch in range(epochs):
        rng.shuffle(train_rows)
        for x, target in train_rows:
            hidden = [sigmoid(sum(w * v for w, v in zip(weights, x)) + bias)
                      for weights, bias in zip(hw, hb)]
            probs = softmax([sum(w * v for w, v in zip(weights, hidden)) + bias
                             for weights, bias in zip(ow, ob)])
            out_delta = [p - (1.0 if j == target else 0.0) for j, p in enumerate(probs)]
            hidden_delta = [h * (1.0 - h) * sum(ow[j][i] * out_delta[j] for j in range(3))
                            for i, h in enumerate(hidden)]
            for j in range(3):
                for i in range(hidden_size):
                    ow[j][i] -= learning_rate * out_delta[j] * hidden[i]
                ob[j] -= learning_rate * out_delta[j]
            for i in range(hidden_size):
                for j in range(n_features):
                    hw[i][j] -= learning_rate * hidden_delta[i] * x[j]
                hb[i] -= learning_rate * hidden_delta[i]

    def classify(x: list[float]) -> int:
        hidden = [sigmoid(sum(w * v for w, v in zip(weights, x)) + bias)
                  for weights, bias in zip(hw, hb)]
        probs = softmax([sum(w * v for w, v in zip(weights, hidden)) + bias
                         for weights, bias in zip(ow, ob)])
        return max(range(3), key=probs.__getitem__)

    correct = sum(classify(x) == target for x, target in valid_rows)
    accuracy = correct / len(valid_rows)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with DATASET_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([*FEATURES, "label"])
        writer.writerows([*map(lambda value: f"{value:.6f}", x), LABELS[target]] for x, target in rows)
    artifact = {
        "format": 1, "description": "Synthetic structural-pattern classifier; auxiliary estimate, not a real-world benchmark.",
        "feature_names": list(FEATURES), "labels": list(LABELS),
        "class_scores": [20, 55, 88], "hidden_weights": hw, "hidden_bias": hb,
        "output_weights": ow, "output_bias": ob,
        "training": {"examples": len(rows), "train_examples": len(train_rows),
                     "validation_examples": len(valid_rows), "validation_accuracy": round(accuracy, 4),
                     "seed": seed, "epochs": epochs, "dataset": DATASET_PATH.name,
                     "privacy": "Only synthetic feature vectors and class labels are saved; no password text."},
    }
    MODEL_PATH.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    return artifact["training"]


if __name__ == "__main__":
    print(json.dumps(train(), indent=2))
