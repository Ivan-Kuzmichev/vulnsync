"""Top-level entry for the source code analysis component (chapter 3.3)."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .ast_detector import deduplicate, detect
from .patterns import CWE_DESCRIPTIONS


@dataclass
class Vulnerability:
    cwe: str
    cwe_description: str
    line: int
    col: int
    function: str
    snippet: str
    probability: float
    confidence: float
    rationale: str

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_code(source: str) -> list[Vulnerability]:
    """Return list of vulnerabilities found in the given Python source."""
    findings = deduplicate(detect(source))
    out: list[Vulnerability] = []
    for f in findings:
        if f.cwe == "CWE-PARSE":
            continue
        out.append(
            Vulnerability(
                cwe=f.cwe,
                cwe_description=CWE_DESCRIPTIONS.get(f.cwe, "Unknown"),
                line=f.line,
                col=f.col,
                function=f.function,
                snippet=f.snippet,
                probability=f.confidence,
                confidence=f.confidence,
                rationale=f.rationale,
            )
        )
    out.sort(key=lambda v: (-v.probability, v.line))
    return out
