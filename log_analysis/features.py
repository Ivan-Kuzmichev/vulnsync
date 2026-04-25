"""Feature engineering on log events for anomaly and attack classifiers."""

from __future__ import annotations

import re
from urllib.parse import unquote

import numpy as np

from .parser import LogEvent


_SQLI_KEYWORDS = re.compile(
    r"(\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bdelete\b|\bor\s+1\s*=\s*1\b|--|/\*|;\s*shutdown)",
    re.IGNORECASE,
)
_XSS_KEYWORDS = re.compile(
    r"(<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+onerror|<svg[^>]+on)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|/etc/passwd|/windows/win\.ini)", re.IGNORECASE)
_CMD_INJECTION = re.compile(r"(;\s*cat\s|;\s*ls\s|\|\s*nc\s|`[^`]+`|\$\([^)]+\))", re.IGNORECASE)


def event_features(ev: LogEvent) -> np.ndarray:
    """Per-request features. Returns a fixed-length numeric vector."""
    decoded = unquote(ev.path + "?" + ev.query)
    length = len(ev.path) + len(ev.query)
    digits = sum(c.isdigit() for c in decoded)
    letters = sum(c.isalpha() for c in decoded)
    specials = sum(not c.isalnum() and not c.isspace() for c in decoded)
    sqli_hits = len(_SQLI_KEYWORDS.findall(decoded))
    xss_hits = len(_XSS_KEYWORDS.findall(decoded))
    pt_hits = len(_PATH_TRAVERSAL.findall(decoded))
    cmd_hits = len(_CMD_INJECTION.findall(decoded))
    return np.array(
        [
            length,
            digits / max(length, 1),
            letters / max(length, 1),
            specials / max(length, 1),
            sqli_hits,
            xss_hits,
            pt_hits,
            cmd_hits,
            ev.status // 100,  # status class (2,3,4,5)
            len(ev.user_agent),
            int(ev.method == "GET"),
            int(ev.method == "POST"),
            int(ev.size),
        ],
        dtype=np.float32,
    )


FEATURE_NAMES = [
    "url_length",
    "digit_ratio",
    "letter_ratio",
    "special_ratio",
    "sqli_keywords",
    "xss_keywords",
    "path_traversal_markers",
    "cmd_injection_markers",
    "status_class",
    "ua_length",
    "is_get",
    "is_post",
    "size",
]
