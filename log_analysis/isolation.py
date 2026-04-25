"""Isolation Forest anomaly detector — second tier of the ensemble."""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from .features import event_features
from .parser import LogEvent


class IsolationDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, events: list[LogEvent]) -> "IsolationDetector":
        if len(events) < 5:
            return self  # not enough data; fall back to no-op
        X = np.stack([event_features(ev) for ev in events])
        self.model.fit(X)
        self._fitted = True
        return self

    def score(self, ev: LogEvent) -> float:
        """Return anomaly score in [0, 1] (higher = more anomalous)."""
        if not self._fitted:
            return 0.0
        x = event_features(ev).reshape(1, -1)
        # decision_function: higher = more normal. Convert to [0, 1] anomaly.
        raw = self.model.decision_function(x)[0]
        # Squash via sigmoid-ish: typical raw range ~[-0.5, 0.5]
        score = 1.0 / (1.0 + np.exp(8.0 * raw))
        return float(score)
