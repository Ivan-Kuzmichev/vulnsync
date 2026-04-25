"""Statistical thresholds (Table 3.1 from chapter 3.4.2) plus signature detection.

The signature layer catches known attack payloads regardless of what the
ML detectors say — this corresponds to the "third tier" of statistical
metrics from chapter 3.4.2 plus attack-specific markers from chapter 3.4.3.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Iterable
from urllib.parse import unquote

from .parser import LogEvent


_SIGNATURE_RULES = [
    # (regex, score, label)
    (re.compile(r"\bunion\s+select\b", re.IGNORECASE), 0.92, "SQL UNION SELECT"),
    (re.compile(r"\b(or|and)\s+1\s*=\s*1\b", re.IGNORECASE), 0.90, "tautology OR/AND 1=1"),
    (re.compile(r";\s*(drop|truncate|shutdown)\s+", re.IGNORECASE), 0.95, "destructive SQL"),
    (re.compile(r"information_schema\.", re.IGNORECASE), 0.88, "information_schema disclosure"),
    (re.compile(r"<script", re.IGNORECASE), 0.88, "<script> injection"),
    (re.compile(r"<svg[^>]*onload", re.IGNORECASE), 0.88, "SVG onload XSS"),
    (re.compile(r"<img[^>]*onerror", re.IGNORECASE), 0.88, "img onerror XSS"),
    (re.compile(r"javascript:", re.IGNORECASE), 0.80, "javascript: protocol"),
    (re.compile(r"\.\./|\.\.\\"), 0.82, "path traversal"),
    (re.compile(r"/etc/passwd|/etc/shadow|win\.ini", re.IGNORECASE), 0.90, "sensitive file access"),
    (re.compile(r";\s*(cat|ls|nc|wget|curl)\s+", re.IGNORECASE), 0.88, "command chaining"),
    (re.compile(r"`[^`]+`|\$\([^)]+\)"), 0.85, "command substitution"),
]

_SCANNER_UAS = re.compile(
    r"(sqlmap|nikto|zaproxy|nessus|acunetix|burpsuite|nuclei|wfuzz)",
    re.IGNORECASE,
)


def signature_anomaly(ev: LogEvent) -> tuple[float, list[str]]:
    """Match attack signatures in the request URL/UA. Returns (score, hits)."""
    decoded = unquote(ev.path + ("?" + ev.query if ev.query else ""))
    score = 0.0
    hits: list[str] = []
    for pattern, p_score, label in _SIGNATURE_RULES:
        if pattern.search(decoded):
            score = max(score, p_score)
            hits.append(label)
    if _SCANNER_UAS.search(ev.user_agent):
        score = max(score, 0.78)
        hits.append("scanner UA")
    return score, hits


def session_stats(events: Iterable[LogEvent]) -> dict[str, dict]:
    """Compute per-IP session statistics used by the statistical detector."""


def session_stats(events: Iterable[LogEvent]) -> dict[str, dict]:
    """Compute per-IP session statistics used by the statistical detector."""
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for ev in events:
        by_ip[ev.ip].append(ev)

    stats: dict[str, dict] = {}
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        statuses = Counter(ev.status for ev in evs)
        unauthorized = statuses.get(401, 0) + statuses.get(403, 0)
        total = len(evs)
        ua_variants = len(set(ev.user_agent for ev in evs))
        unique_paths = len(set(ev.path for ev in evs))

        # Failed-login burst: count windows where >=10 401-responses in 60s
        burst = False
        timestamps_401 = [ev.timestamp for ev in evs if ev.status == 401]
        for i in range(len(timestamps_401)):
            j = i
            while j < len(timestamps_401) and timestamps_401[j] - timestamps_401[i] <= timedelta(seconds=60):
                j += 1
            if j - i >= 10:
                burst = True
                break

        stats[ip] = {
            "total_requests": total,
            "unauthorized_ratio": unauthorized / max(total, 1),
            "ua_variants": ua_variants,
            "unique_paths": unique_paths,
            "failed_login_burst": burst,
        }
    return stats


def statistical_anomaly(ev: LogEvent, stats: dict[str, dict]) -> tuple[float, list[str]]:
    """Return (score in [0,1], list of triggered rule names)."""
    s = stats.get(ev.ip, {})
    triggered: list[str] = []
    score = 0.0

    if s.get("unauthorized_ratio", 0.0) > 0.05:
        score = max(score, 0.6)
        triggered.append(f"unauthorized_ratio={s['unauthorized_ratio']:.2f} > 0.05")

    if s.get("ua_variants", 0) > 50:
        score = max(score, 0.7)
        triggered.append(f"ua_variants={s['ua_variants']} > 50")

    if s.get("unique_paths", 0) > 200:
        score = max(score, 0.65)
        triggered.append(f"unique_paths={s['unique_paths']} > 200")

    if s.get("failed_login_burst"):
        score = max(score, 0.85)
        triggered.append("failed_login_burst (>=10 status=401 в окне 60с)")

    if ev.status in (401, 403):
        score = max(score, 0.3)

    return score, triggered
