"""Top-level entry for the log analysis component (chapter 3.4).

Combines four signals into a single anomaly verdict per event:
  1. Signature matches (regex against canonical attack payloads)
  2. Statistical thresholds (Table 3.1)
  3. Isolation Forest on per-event features
  4. MLP autoencoder reconstruction error (LSTM substitute)

Plus an attack-type classifier (Gradient Boosting) for CWE labeling.

The ML models are trained on the input itself, but only on requests that
look benign by signature/statistics — otherwise on a small demo log they
would learn the attacks as normal traffic.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .autoencoder import BehavioralAutoencoder
from .classifier import AttackClassifier
from .isolation import IsolationDetector
from .parser import LogEvent, parse
from .statistical import (
    session_stats,
    signature_anomaly,
    statistical_anomaly,
)


# Weights from chapter 3.4.2 plus an explicit signature lane.
# Final per-event score = max(W_SIG * s_sig, W_STAT*s_stat + W_AUTO*s_auto + W_ISO*s_iso)
W_STAT = 0.30
W_AUTO = 0.40
W_ISO = 0.30
ANOMALY_THRESHOLD = 0.55


@dataclass
class LogAnomaly:
    line_no: int
    timestamp: str
    ip: str
    method: str
    path: str
    status: int
    user_agent: str
    raw: str
    anomaly_score: float
    attack_type: str
    classifier_confidence: float
    triggered_rules: list[str]
    breakdown: dict
    decoded_path: str

    def to_dict(self) -> dict:
        return asdict(self)


def _decoded(ev: LogEvent) -> str:
    return ev.path + (("?" + ev.query) if ev.query else "")


def _benign_subset(events: list[LogEvent]) -> list[LogEvent]:
    """Filter events that look benign — used as training set for ML models."""
    benign: list[LogEvent] = []
    for ev in events:
        sig_score, _ = signature_anomaly(ev)
        if sig_score >= 0.5:
            continue
        if ev.status >= 500:
            continue
        if ev.status in (401, 403):
            continue
        benign.append(ev)
    return benign


def analyze_logs(text: str) -> dict:
    """Parse logs and return aggregated analysis."""
    events = parse(text)
    total = len(events)
    if total == 0:
        return {
            "total_events": 0,
            "anomalies": [],
            "top_attack": "BENIGN",
            "aggregate_score": 0.0,
        }

    training_set = _benign_subset(events) or events
    iso = IsolationDetector(contamination=0.05).fit(training_set)
    auto = BehavioralAutoencoder(hidden_dim=8).fit(training_set)
    classifier = AttackClassifier().fit()
    stats = session_stats(events)

    anomalies: list[LogAnomaly] = []
    for ev in events:
        s_sig, sig_hits = signature_anomaly(ev)
        s_stat, stat_triggered = statistical_anomaly(ev, stats)
        s_iso = iso.score(ev)
        s_auto = auto.score(ev)
        ml_score = W_STAT * s_stat + W_AUTO * s_auto + W_ISO * s_iso
        score = max(s_sig, ml_score)

        triggered = stat_triggered + sig_hits
        if score < ANOMALY_THRESHOLD and not triggered:
            continue

        attack_type, classifier_conf = classifier.predict(ev)

        # Override classifier with signature-derived label when the signature
        # is unambiguous — signatures are a higher-confidence source.
        if any("SQL" in h or "tautology" in h or "schema" in h for h in sig_hits):
            attack_type, classifier_conf = "CWE-89", max(classifier_conf, 0.92)
        elif any("script" in h or "XSS" in h or "javascript" in h for h in sig_hits):
            attack_type, classifier_conf = "CWE-79", max(classifier_conf, 0.92)
        elif any("traversal" in h or "sensitive file" in h for h in sig_hits):
            attack_type, classifier_conf = "CWE-22", max(classifier_conf, 0.90)
        elif any("command" in h for h in sig_hits):
            attack_type, classifier_conf = "CWE-78", max(classifier_conf, 0.88)
        elif any("failed_login_burst" in r for r in stat_triggered):
            attack_type, classifier_conf = "CWE-307", max(classifier_conf, 0.85)

        anomalies.append(
            LogAnomaly(
                line_no=ev.line_no,
                timestamp=ev.timestamp.isoformat(),
                ip=ev.ip,
                method=ev.method,
                path=ev.path,
                status=ev.status,
                user_agent=ev.user_agent,
                raw=ev.raw,
                anomaly_score=round(float(score), 3),
                attack_type=attack_type,
                classifier_confidence=round(float(classifier_conf), 3),
                triggered_rules=triggered,
                breakdown={
                    "signature": round(float(s_sig), 3),
                    "statistical": round(float(s_stat), 3),
                    "isolation_forest": round(float(s_iso), 3),
                    "autoencoder": round(float(s_auto), 3),
                },
                decoded_path=_decoded(ev),
            )
        )

    anomalies.sort(key=lambda a: -a.anomaly_score)

    counts: dict[str, int] = {}
    for a in anomalies:
        if a.attack_type == "BENIGN":
            continue
        counts[a.attack_type] = counts.get(a.attack_type, 0) + 1
    top_attack = max(counts.items(), key=lambda kv: kv[1])[0] if counts else "BENIGN"

    if anomalies:
        avg = sum(a.anomaly_score for a in anomalies) / len(anomalies)
        rate = len(anomalies) / total
        aggregate = min(1.0, avg * (1.0 + rate))
    else:
        aggregate = 0.0

    return {
        "total_events": total,
        "anomalies": anomalies,
        "top_attack": top_attack,
        "aggregate_score": round(float(aggregate), 3),
    }
