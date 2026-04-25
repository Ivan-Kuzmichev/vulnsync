"""Integration layer (chapter 3.5).

Implements the formulas literally:
  Risk = w1*P_code + w2*S_anomaly + w3*Severity(CWE) + w4*Agreement(CWE)
  Confidence = sqrt(C_code * C_log) * (1 + 0.5 * Agreement)

Plus the production-rule decision logic from 3.5.2.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass

from app.code_analysis import Vulnerability
from app.code_analysis.patterns import CWE_DESCRIPTIONS, CWE_SEVERITY


W1 = 0.30  # P_code
W2 = 0.30  # S_anomaly
W3 = 0.20  # Severity
W4 = 0.20  # Agreement


@dataclass
class IntegratedFinding:
    cwe: str
    cwe_description: str
    risk_score: float
    confidence: float
    severity_class: str  # critical / high / medium / low / info
    decision: str
    code_evidence: dict | None
    log_evidence: list[dict]
    rationale: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IntegratedReport:
    overall_risk: float
    overall_confidence: float
    overall_decision: str
    findings: list[IntegratedFinding]

    def to_dict(self) -> dict:
        return {
            "overall_risk": self.overall_risk,
            "overall_confidence": self.overall_confidence,
            "overall_decision": self.overall_decision,
            "findings": [f.to_dict() for f in self.findings],
        }


# CWE family groups for partial agreement.
# Group only closely-related variants — SQL injection cannot validate command
# injection; they are distinct attack vectors despite being in the same
# OWASP umbrella.
_CWE_FAMILIES = {
    "sql_injection": {"CWE-89"},
    "command_injection": {"CWE-78", "CWE-77"},
    "code_injection": {"CWE-94", "CWE-95"},
    "deserialization": {"CWE-502"},
    "xss": {"CWE-79", "CWE-80"},
    "auth": {"CWE-307", "CWE-287", "CWE-352"},
    "traversal": {"CWE-22", "CWE-23"},
    "ssrf": {"CWE-918"},
}


def _agreement(cwe_a: str, cwe_b: str) -> float:
    if cwe_a == cwe_b and cwe_a not in (None, "BENIGN"):
        return 1.0
    fam_a = next((name for name, members in _CWE_FAMILIES.items() if cwe_a in members), None)
    fam_b = next((name for name, members in _CWE_FAMILIES.items() if cwe_b in members), None)
    if fam_a and fam_a == fam_b:
        return 0.6
    return 0.0


def _severity_class(risk: float) -> str:
    if risk >= 0.85:
        return "critical"
    if risk >= 0.65:
        return "high"
    if risk >= 0.45:
        return "medium"
    if risk >= 0.25:
        return "low"
    return "info"


def _decision(risk: float, confidence: float, p_code: float, s_anomaly: float) -> str:
    if risk >= 0.75 and confidence >= 0.7:
        return "Подтвержденная критическая уязвимость — немедленная эскалация."
    if risk >= 0.5:
        return "Уязвимость средней серьезности — верификация аналитиком."
    if p_code >= 0.7 and s_anomaly < 0.3:
        return "Потенциальная уязвимость без признаков эксплуатации — плановое исправление."
    if p_code < 0.3 and s_anomaly >= 0.7:
        return "Аномальная активность без подтверждения уязвимости в коде — расследование в SIEM."
    return "Низкий риск — мониторинг."


def integrate(vulnerabilities: list[Vulnerability], log_report: dict) -> IntegratedReport:
    """Merge code-side and log-side results into a unified report."""
    anomalies = log_report.get("anomalies", [])
    aggregate_log_score = log_report.get("aggregate_score", 0.0)

    findings: list[IntegratedFinding] = []

    # Index anomalies by attack_type
    by_type: dict[str, list] = {}
    for a in anomalies:
        by_type.setdefault(a.attack_type, []).append(a)

    matched_anomaly_ids: set[int] = set()

    # 1. Code findings (cross-correlate with logs)
    for v in vulnerabilities:
        related = by_type.get(v.cwe, [])[:3]
        for r in related:
            matched_anomaly_ids.add(r.line_no)

        agreement = 1.0 if related else 0.0
        if not related:
            # Try family-level match
            for atype, evs in by_type.items():
                if _agreement(v.cwe, atype) > 0:
                    related = evs[:3]
                    matched_anomaly_ids.update(r.line_no for r in related)
                    agreement = _agreement(v.cwe, atype)
                    break

        s_anomaly = max((r.anomaly_score for r in related), default=0.0)
        c_log = max((r.classifier_confidence for r in related), default=0.0)

        p_code = v.probability
        c_code = v.confidence
        severity = CWE_SEVERITY.get(v.cwe, 0.5)

        risk = W1 * p_code + W2 * s_anomaly + W3 * severity + W4 * agreement
        if c_log > 0:
            confidence = math.sqrt(c_code * c_log) * (1.0 + 0.5 * agreement)
        else:
            confidence = c_code * 0.7  # only one source — penalize
        confidence = min(1.0, confidence)

        rationale_parts = [
            f"Анализ кода: {v.cwe} ({CWE_DESCRIPTIONS.get(v.cwe, '')}) "
            f"в функции `{v.function}`, строка {v.line}, P_code={p_code:.2f}.",
            v.rationale,
        ]
        if related:
            rationale_parts.append(
                f"Анализ логов: {len(related)} согласующихся событий "
                f"(тип {related[0].attack_type}, max_score={s_anomaly:.2f}). "
                f"Согласованность Agreement={agreement:.1f}."
            )
        else:
            rationale_parts.append(
                "Анализ логов: сопоставимых событий не обнаружено. "
                "Признаков активной эксплуатации нет."
            )

        findings.append(
            IntegratedFinding(
                cwe=v.cwe,
                cwe_description=v.cwe_description,
                risk_score=round(float(min(1.0, risk)), 3),
                confidence=round(float(confidence), 3),
                severity_class=_severity_class(risk),
                decision=_decision(risk, confidence, p_code, s_anomaly),
                code_evidence={
                    "function": v.function,
                    "line": v.line,
                    "snippet": v.snippet,
                    "p_code": round(float(p_code), 3),
                },
                log_evidence=[r.to_dict() for r in related],
                rationale=" ".join(rationale_parts),
            )
        )

    # 2. Log-only anomalies (no matching code finding) — investigate via SIEM
    code_cwes = {v.cwe for v in vulnerabilities}
    by_attack: dict[str, list] = {}
    for a in anomalies:
        if a.line_no in matched_anomaly_ids:
            continue
        if a.attack_type in code_cwes:
            continue
        if a.attack_type == "BENIGN":
            continue
        by_attack.setdefault(a.attack_type, []).append(a)

    for atype, evs in by_attack.items():
        s_anomaly = max(a.anomaly_score for a in evs)
        c_log = max(a.classifier_confidence for a in evs)
        severity = CWE_SEVERITY.get(atype, 0.5)
        risk = W1 * 0.0 + W2 * s_anomaly + W3 * severity + W4 * 0.0
        confidence = c_log * 0.7  # one source only
        findings.append(
            IntegratedFinding(
                cwe=atype,
                cwe_description=CWE_DESCRIPTIONS.get(atype, atype),
                risk_score=round(float(min(1.0, risk)), 3),
                confidence=round(float(confidence), 3),
                severity_class=_severity_class(risk),
                decision=_decision(risk, confidence, 0.0, s_anomaly),
                code_evidence=None,
                log_evidence=[a.to_dict() for a in evs[:5]],
                rationale=(
                    f"Анализ логов: {len(evs)} аномальных событий типа {atype}. "
                    f"Максимальная аномальность {s_anomaly:.2f}. "
                    "В коде сопоставимых уязвимостей не обнаружено — рекомендуется "
                    "расследование в SIEM или ручная проверка соответствующих обработчиков."
                ),
            )
        )

    findings.sort(key=lambda f: -f.risk_score)

    if findings:
        overall_risk = max(f.risk_score for f in findings)
        overall_confidence = max(f.confidence for f in findings)
    else:
        overall_risk = 0.0
        overall_confidence = 0.0

    overall_decision = (
        findings[0].decision if findings else "Угроз не обнаружено по обоим компонентам."
    )

    return IntegratedReport(
        overall_risk=round(float(overall_risk), 3),
        overall_confidence=round(float(overall_confidence), 3),
        overall_decision=overall_decision,
        findings=findings,
    )
