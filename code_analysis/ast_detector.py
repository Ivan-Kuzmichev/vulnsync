"""AST-based static detector for common web-app vulnerabilities.

Implements the pattern-detection part of the source-code analysis component
described in chapter 3.3. Operates on Python code; detection is intentionally
conservative (high recall on documented patterns, accepts moderate FPR which
is later corrected by the integration layer).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Iterable

from .patterns import (
    DANGEROUS_FUNCTIONS,
    FILE_OPS,
    RENDER_METHODS,
    SQL_METHODS,
    URL_OPS,
)


@dataclass
class Finding:
    cwe: str
    line: int
    col: int
    function: str
    snippet: str
    confidence: float
    rationale: str


def _qualified_name(node: ast.AST) -> str | None:
    """Return dotted name for a Call.func, e.g. 'os.system' or 'cursor.execute'."""
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST | None = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        return None
    if isinstance(node, ast.Name):
        return node.id
    return None


_TAINT_PREFIXES = (
    "request.args",
    "request.form",
    "request.json",
    "request.values",
    "request.cookies",
    "request.headers",
    "request.GET",
    "request.POST",
    "flask.request",
)


def _is_taint_source(node: ast.AST) -> bool:
    """Direct check: is this node a taint source (no variable propagation)."""
    if isinstance(node, ast.Attribute):
        qn = _qualified_name(node)
        if qn and any(qn.startswith(p) for p in _TAINT_PREFIXES):
            return True
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Attribute):
            qn = _qualified_name(node.value)
            if qn and qn.startswith("request."):
                return True
    if isinstance(node, ast.Call):
        qn = _qualified_name(node.func)
        if qn == "input":
            return True
        # request.args.get(...), request.form.get(...)
        if isinstance(node.func, ast.Attribute):
            inner = node.func.value
            if isinstance(inner, ast.Attribute):
                qn = _qualified_name(inner)
                if qn and any(qn.startswith(p) for p in _TAINT_PREFIXES):
                    return True
    return False


def _collect_tainted_vars(tree: ast.Module) -> set[str]:
    """Walk all assignments; mark variables assigned from a taint source.

    Single-pass, no fixed-point iteration. Catches one-step propagation:
        name = request.args.get('foo')
        path = "/var/" + name        # 'path' becomes tainted via 'name'
    Sufficient for the demo scope; full taint analysis is out of scope.
    """
    tainted: set[str] = set()
    # Two passes for one-step transitive propagation.
    for _ in range(2):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            if _expr_uses_tainted(value, tainted):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        tainted.add(target.id)
    return tainted


def _expr_uses_tainted(expr: ast.AST, tainted_vars: set[str]) -> bool:
    """Does this expression reference a taint source or a tainted variable?"""
    for sub in ast.walk(expr):
        if _is_taint_source(sub):
            return True
        if isinstance(sub, ast.Name) and sub.id in tainted_vars:
            return True
        if isinstance(sub, ast.Name) and sub.id in {"argv", "stdin"}:
            return True
    return False


def _is_user_tainted(node: ast.AST, tainted_vars: set[str] | None = None) -> bool:
    return _expr_uses_tainted(node, tainted_vars or set())


def _is_dynamic_string(node: ast.AST) -> bool:
    """Detect non-constant string construction: f-strings, %-formatting, +, .format()."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return True
    return False


def _enclosing_function(tree: ast.Module, target: ast.AST) -> str:
    """Return name of the function containing target, or '<module>'."""
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    cur: ast.AST | None = target
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return cur.name
        cur = parents.get(id(cur))
    return "<module>"


def _snippet(source_lines: list[str], line: int, context: int = 1) -> str:
    start = max(0, line - 1 - context)
    end = min(len(source_lines), line + context)
    return "\n".join(source_lines[start:end])


def detect(source: str) -> list[Finding]:
    """Run all detectors over Python source. Returns list of findings."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [
            Finding(
                cwe="CWE-PARSE",
                line=exc.lineno or 0,
                col=exc.offset or 0,
                function="<module>",
                snippet=str(exc.msg),
                confidence=0.0,
                rationale="Не удалось разобрать код (SyntaxError).",
            )
        ]

    source_lines = source.splitlines()
    findings: list[Finding] = []
    tainted_vars = _collect_tainted_vars(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qn = _qualified_name(node.func)
        if qn is None:
            continue

        # Direct dangerous calls (eval, exec, os.system, ...)
        if qn in DANGEROUS_FUNCTIONS:
            cwe = DANGEROUS_FUNCTIONS[qn]
            tainted = any(_is_user_tainted(arg, tainted_vars) for arg in node.args)
            confidence = 0.85 if tainted else 0.55
            rationale = (
                f"Вызов опасной функции `{qn}` с пользовательским вводом."
                if tainted
                else f"Вызов опасной функции `{qn}` (не подтвержден taint, но опасный API)."
            )
            findings.append(
                Finding(
                    cwe=cwe,
                    line=node.lineno,
                    col=node.col_offset,
                    function=_enclosing_function(tree, node),
                    snippet=_snippet(source_lines, node.lineno),
                    confidence=confidence,
                    rationale=rationale,
                )
            )
            continue

        # SQL execution with dynamic query
        method = qn.split(".")[-1] if qn else ""
        if method in SQL_METHODS and node.args:
            first_arg = node.args[0]
            if _is_dynamic_string(first_arg) and _is_user_tainted(first_arg, tainted_vars):
                findings.append(
                    Finding(
                        cwe="CWE-89",
                        line=node.lineno,
                        col=node.col_offset,
                        function=_enclosing_function(tree, node),
                        snippet=_snippet(source_lines, node.lineno),
                        confidence=0.88,
                        rationale=(
                            "Динамическая SQL-строка с пользовательским вводом, "
                            "переданная в `cursor.execute()` без параметризации."
                        ),
                    )
                )
            elif _is_dynamic_string(first_arg):
                findings.append(
                    Finding(
                        cwe="CWE-89",
                        line=node.lineno,
                        col=node.col_offset,
                        function=_enclosing_function(tree, node),
                        snippet=_snippet(source_lines, node.lineno),
                        confidence=0.55,
                        rationale=(
                            "Динамически построенная SQL-строка. Источник "
                            "пользовательского ввода не подтвержден."
                        ),
                    )
                )
            continue

        # Render with user input -> XSS
        if method in RENDER_METHODS and node.args:
            first_arg = node.args[0]
            if _is_user_tainted(first_arg, tainted_vars) or _is_dynamic_string(first_arg):
                findings.append(
                    Finding(
                        cwe="CWE-79",
                        line=node.lineno,
                        col=node.col_offset,
                        function=_enclosing_function(tree, node),
                        snippet=_snippet(source_lines, node.lineno),
                        confidence=0.80,
                        rationale=(
                            f"Передача пользовательских данных в `{method}` без "
                            "экранирования; HTML-контекст подразумевает риск XSS."
                        ),
                    )
                )
            continue

        # File ops with tainted path -> path traversal
        if method in FILE_OPS and node.args:
            first_arg = node.args[0]
            if _is_user_tainted(first_arg, tainted_vars):
                findings.append(
                    Finding(
                        cwe="CWE-22",
                        line=node.lineno,
                        col=node.col_offset,
                        function=_enclosing_function(tree, node),
                        snippet=_snippet(source_lines, node.lineno),
                        confidence=0.78,
                        rationale=(
                            f"Файловая операция `{method}` принимает путь, "
                            "построенный из пользовательского ввода — возможен Path Traversal."
                        ),
                    )
                )
            continue

        # URL ops with tainted target -> SSRF
        if method in URL_OPS and node.args:
            first_arg = node.args[0]
            if _is_user_tainted(first_arg, tainted_vars):
                findings.append(
                    Finding(
                        cwe="CWE-918",
                        line=node.lineno,
                        col=node.col_offset,
                        function=_enclosing_function(tree, node),
                        snippet=_snippet(source_lines, node.lineno),
                        confidence=0.74,
                        rationale=(
                            f"HTTP-запрос (`{method}`) на URL из пользовательского "
                            "ввода без валидации схемы и хоста — возможен SSRF."
                        ),
                    )
                )
            continue

    # Subprocess with shell=True is special
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qn = _qualified_name(node.func)
        if qn and qn.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append(
                        Finding(
                            cwe="CWE-78",
                            line=node.lineno,
                            col=node.col_offset,
                            function=_enclosing_function(tree, node),
                            snippet=_snippet(source_lines, node.lineno),
                            confidence=0.82,
                            rationale=(
                                f"Вызов `{qn}` с `shell=True` — классический "
                                "вектор инъекции команд ОС."
                            ),
                        )
                    )
    return findings


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Remove duplicate findings on the same (cwe, line)."""
    seen: dict[tuple[str, int], Finding] = {}
    for f in findings:
        key = (f.cwe, f.line)
        prev = seen.get(key)
        if prev is None or f.confidence > prev.confidence:
            seen[key] = f
    return list(seen.values())
