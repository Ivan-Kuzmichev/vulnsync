"""Attack-type classifier (XGBoost) — chapter 3.4.3.

Trains on a synthetic dataset generated from canonical attack signatures.
This is sufficient for the demonstration; in production it would be replaced
with a model trained on CSIC 2010 / CICIDS 2017 / proprietary honeypot data.
"""

from __future__ import annotations

import warnings

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier

from .features import event_features
from .parser import LogEvent


CWE_LABELS = ["BENIGN", "CWE-89", "CWE-79", "CWE-22", "CWE-78", "CWE-307"]


def _synthetic_training_set() -> tuple[np.ndarray, np.ndarray]:
    """Generate a small but discriminative training set from feature templates."""
    rng = np.random.default_rng(42)
    rows: list[np.ndarray] = []
    labels: list[int] = []

    # Pattern: [length, digit_r, letter_r, special_r, sqli, xss, pt, cmd,
    #          status_class, ua_len, is_get, is_post, size]
    patterns = {
        # BENIGN
        0: lambda: [
            rng.integers(20, 60),
            rng.uniform(0.05, 0.25),
            rng.uniform(0.4, 0.8),
            rng.uniform(0.05, 0.2),
            0, 0, 0, 0, 2,
            rng.integers(40, 200),
            1, 0,
            rng.integers(500, 5000),
        ],
        # SQLi
        1: lambda: [
            rng.integers(60, 200),
            rng.uniform(0.05, 0.2),
            rng.uniform(0.3, 0.6),
            rng.uniform(0.15, 0.4),
            rng.integers(1, 4),
            0, 0, 0, 2,
            rng.integers(40, 200),
            1, 0,
            rng.integers(0, 3000),
        ],
        # XSS
        2: lambda: [
            rng.integers(60, 200),
            rng.uniform(0.0, 0.15),
            rng.uniform(0.3, 0.6),
            rng.uniform(0.15, 0.45),
            0,
            rng.integers(1, 4),
            0, 0, 2,
            rng.integers(40, 200),
            1, 0,
            rng.integers(0, 3000),
        ],
        # Path Traversal
        3: lambda: [
            rng.integers(40, 150),
            rng.uniform(0.0, 0.2),
            rng.uniform(0.3, 0.7),
            rng.uniform(0.15, 0.4),
            0, 0,
            rng.integers(1, 3),
            0,
            rng.choice([2, 4]),
            rng.integers(40, 200),
            1, 0,
            rng.integers(0, 1000),
        ],
        # Command injection
        4: lambda: [
            rng.integers(50, 150),
            rng.uniform(0.0, 0.2),
            rng.uniform(0.3, 0.6),
            rng.uniform(0.2, 0.5),
            0, 0, 0,
            rng.integers(1, 3),
            rng.choice([2, 4]),
            rng.integers(40, 200),
            1, 0,
            rng.integers(0, 1000),
        ],
        # Brute force (status 401, normal-looking URL)
        5: lambda: [
            rng.integers(15, 40),
            rng.uniform(0.05, 0.2),
            rng.uniform(0.5, 0.8),
            rng.uniform(0.05, 0.15),
            0, 0, 0, 0, 4,
            rng.integers(40, 200),
            0, 1,
            rng.integers(0, 200),
        ],
    }

    samples_per_class = 200
    for label, gen in patterns.items():
        for _ in range(samples_per_class):
            rows.append(np.array(gen(), dtype=np.float32))
            labels.append(label)

    return np.stack(rows), np.array(labels)


class AttackClassifier:
    def __init__(self):
        self.model = GradientBoostingClassifier(
            n_estimators=80,
            max_depth=4,
            learning_rate=0.2,
            random_state=42,
        )
        self._fitted = False

    def fit(self) -> "AttackClassifier":
        X, y = _synthetic_training_set()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.model.fit(X, y)
        self._fitted = True
        return self

    def predict(self, ev: LogEvent) -> tuple[str, float]:
        if not self._fitted:
            return "BENIGN", 0.5
        x = event_features(ev).reshape(1, -1)
        probs = self.model.predict_proba(x)[0]
        idx = int(np.argmax(probs))
        return CWE_LABELS[idx], float(probs[idx])
