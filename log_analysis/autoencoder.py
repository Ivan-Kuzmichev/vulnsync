"""Sequence autoencoder for behavioral anomaly detection.

The dissertation describes an LSTM autoencoder. To keep the prototype
lightweight (no PyTorch) we implement an MLP autoencoder via sklearn's
MLPRegressor where input == output. The objective is reconstruction error;
the architecture is an implementation detail. For production use this
class can be swapped for a PyTorch LSTM with the same fit/score interface.
"""

from __future__ import annotations

import warnings

import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from .features import event_features
from .parser import LogEvent


class BehavioralAutoencoder:
    def __init__(self, hidden_dim: int = 8, random_state: int = 42):
        self.hidden_dim = hidden_dim
        self.scaler = StandardScaler()
        self.model = MLPRegressor(
            hidden_layer_sizes=(hidden_dim,),
            activation="tanh",
            solver="adam",
            max_iter=200,
            random_state=random_state,
            tol=1e-4,
        )
        self._threshold: float | None = None
        self._fitted = False

    def _build_matrix(self, events: list[LogEvent]) -> np.ndarray:
        return np.stack([event_features(ev) for ev in events])

    def fit(self, events: list[LogEvent]) -> "BehavioralAutoencoder":
        if len(events) < 10:
            return self
        X = self._build_matrix(events)
        Xs = self.scaler.fit_transform(X)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            # Train as autoencoder: target == input
            self.model.fit(Xs, Xs)
        recon = self.model.predict(Xs)
        errors = np.mean((Xs - recon) ** 2, axis=1)
        # Threshold = 95th percentile of training errors
        self._threshold = float(np.percentile(errors, 95))
        self._fitted = True
        return self

    def score(self, ev: LogEvent) -> float:
        """Return anomaly score in [0, 1] based on reconstruction error."""
        if not self._fitted or self._threshold is None:
            return 0.0
        x = self.scaler.transform(event_features(ev).reshape(1, -1))
        recon = self.model.predict(x)
        err = float(np.mean((x - recon) ** 2))
        # Normalize: error == threshold -> 0.5, error == 3*threshold -> ~0.95
        ratio = err / max(self._threshold, 1e-6)
        return float(1.0 / (1.0 + np.exp(-1.5 * (ratio - 1.0))))
