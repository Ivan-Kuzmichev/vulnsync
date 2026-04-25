"""Top-level entry for the source code analysis component (chapter 3.3).

Runs AST-based pattern detection. When WITH_BERT=1 and a trained head is
available, also runs the GraphCodeBERT scorer in parallel and combines:

  - For each AST finding, boost confidence if BERT also flags the
    enclosing function (max(P_ast, P_bert)).
  - For each function with BERT P_vuln >= 0.7 that AST didn't flag, emit
    a finding with cwe="CWE-UNKNOWN" so the integration layer can still
    cross-reference it with logs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .ast_detector import deduplicate, detect
from .bert_scorer import FunctionScore, get_scorer, is_enabled
from .patterns import CWE_DESCRIPTIONS


BERT_THRESHOLD_NEW_FINDING = 0.70  # Min BERT score to emit new (no-AST) finding
BERT_BOOST_THRESHOLD = 0.50        # BERT score above which we raise AST confidence


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
    bert_score: float | None = None
    ast_score: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _enclosing_bert_score(line: int, scores: list[FunctionScore]) -> FunctionScore | None:
    for s in scores:
        if s.line <= line <= s.end_line:
            return s
    return None


def analyze_code(source: str) -> list[Vulnerability]:
    """Return list of vulnerabilities. Combines AST + (optional) BERT."""
    findings = deduplicate(detect(source))

    bert_scores: list[FunctionScore] = []
    scorer = get_scorer()
    if scorer is not None:
        try:
            bert_scores = scorer.score_functions(source)
        except Exception as exc:  # noqa: BLE001
            print(f"[analyze_code] BERT scoring failed: {exc}")
            bert_scores = []

    out: list[Vulnerability] = []
    flagged_functions: set[str] = set()

    for f in findings:
        if f.cwe == "CWE-PARSE":
            continue
        bert = _enclosing_bert_score(f.line, bert_scores)
        bert_p = bert.p_vulnerable if bert else None
        ast_p = f.confidence

        if bert_p is not None and bert_p >= BERT_BOOST_THRESHOLD:
            probability = max(ast_p, bert_p)
            extra = f" BERT score: {bert_p:.2f} подтверждает."
        elif bert_p is not None:
            probability = ast_p * 0.85
            extra = f" BERT score: {bert_p:.2f} (низкая уверенность модели — возможен FP)."
        else:
            probability = ast_p
            extra = ""

        if bert is not None:
            flagged_functions.add(bert.function)

        out.append(
            Vulnerability(
                cwe=f.cwe,
                cwe_description=CWE_DESCRIPTIONS.get(f.cwe, "Unknown"),
                line=f.line,
                col=f.col,
                function=f.function,
                snippet=f.snippet,
                probability=probability,
                confidence=probability,
                rationale=f.rationale + extra,
                bert_score=bert_p,
                ast_score=ast_p,
            )
        )

    # BERT-only findings: function flagged by model but AST missed it
    if scorer is not None:
        for s in bert_scores:
            if s.function in flagged_functions:
                continue
            if s.p_vulnerable < BERT_THRESHOLD_NEW_FINDING:
                continue
            out.append(
                Vulnerability(
                    cwe="CWE-UNKNOWN",
                    cwe_description="Подозрительная функция (детектор ML)",
                    line=s.line,
                    col=0,
                    function=s.function,
                    snippet=s.snippet,
                    probability=s.p_vulnerable,
                    confidence=s.p_vulnerable * 0.8,  # one source only
                    rationale=(
                        f"GraphCodeBERT classifier помечает функцию `{s.function}` "
                        f"как уязвимую (P={s.p_vulnerable:.2f}), но AST-детектор "
                        "не нашёл известного паттерна. Требует ручной проверки."
                    ),
                    bert_score=s.p_vulnerable,
                    ast_score=None,
                )
            )

    out.sort(key=lambda v: (-v.probability, v.line))
    return out


def get_status() -> dict:
    """Returns current analyzer configuration — useful for /healthz, debugging."""
    return {
        "ast_enabled": True,
        "bert_enabled": is_enabled(),
        "bert_loaded": get_scorer() is not None,
    }
