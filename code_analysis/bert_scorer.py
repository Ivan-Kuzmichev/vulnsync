"""GraphCodeBERT-based vulnerability scorer (opt-in via WITH_BERT=1).

Loads frozen GraphCodeBERT encoder + a fine-tuned classification head and
returns per-function P(vulnerable). Used by `analyzer.py` as a second
signal alongside the AST detector.

The scorer is loaded lazily on first call (singleton) and cached for the
process lifetime to avoid re-loading the 500 MB model.
"""

from __future__ import annotations

import ast
import functools
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


_BASE = Path(__file__).resolve().parent.parent
_DEFAULT_HEAD = _BASE / "models" / "vuln_head.pt"


@dataclass
class FunctionScore:
    function: str
    line: int
    end_line: int
    p_vulnerable: float
    snippet: str


def _device():
    import torch
    if torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


class _BertScorerImpl:
    """Holds tokenizer, encoder, head. Heavy — instantiate via `get_scorer()`."""

    def __init__(self, head_path: Path = _DEFAULT_HEAD):
        import torch
        from transformers import AutoModel, AutoTokenizer
        self._torch = torch
        if not head_path.exists():
            raise FileNotFoundError(
                f"Head weights not found at {head_path}. "
                "Run `python -m code_analysis.train_head` first (see BERT_PLAN.md)."
            )

        self.device = _device()
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
        self.encoder = AutoModel.from_pretrained("microsoft/graphcodebert-base").to(self.device)
        self.encoder.eval()
        for p in self.encoder.parameters():
            p.requires_grad = False

        ckpt = torch.load(head_path, map_location=self.device, weights_only=False)
        num_classes = ckpt.get("num_classes", 2)
        self.head = self._build_head(num_classes).to(self.device)
        self.head.load_state_dict(ckpt["state_dict"])
        self.head.eval()
        self.labels = ckpt.get("labels", ["BENIGN", "VULNERABLE"])
        self.head_metrics = {"best_f1": ckpt.get("best_f1")}

    def _build_head(self, num_classes: int):
        torch = self._torch
        return torch.nn.Sequential(
            torch.nn.Linear(768, 256),
            torch.nn.Tanh(),
            torch.nn.Dropout(0.3),
            torch.nn.Linear(256, num_classes),
        )

    def _embed(self, codes: list[str]):
        torch = self._torch
        enc = self.tokenizer(
            codes,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
        ).to(self.device)
        with torch.no_grad():
            out = self.encoder(**enc)
        return out.last_hidden_state[:, 0, :]

    def score_functions(self, source: str) -> list[FunctionScore]:
        """Split `source` into top-level functions, return per-function P_vuln."""
        torch = self._torch
        units = _extract_functions(source)
        if not units:
            return []
        embeddings = self._embed([u.code for u in units])
        with torch.no_grad():
            logits = self.head(embeddings)
            probs = torch.softmax(logits, dim=-1).cpu().tolist()
        scores: list[FunctionScore] = []
        for u, p in zip(units, probs):
            # Index 1 corresponds to VULNERABLE label by training convention.
            p_vuln = float(p[1]) if len(p) > 1 else float(p[0])
            scores.append(
                FunctionScore(
                    function=u.name,
                    line=u.line,
                    end_line=u.end_line,
                    p_vulnerable=p_vuln,
                    snippet=u.code,
                )
            )
        return scores


@dataclass
class _Func:
    name: str
    line: int
    end_line: int
    code: str


def _extract_functions(source: str) -> list[_Func]:
    """Pull top-level def/async def + class methods from Python source."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    funcs: list[_Func] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno - 1
            end = (getattr(node, "end_lineno", None) or node.lineno) - 1
            snippet = "\n".join(lines[start : end + 1])
            funcs.append(_Func(name=node.name, line=node.lineno, end_line=end + 1, code=snippet))
    return funcs


@functools.lru_cache(maxsize=1)
def get_scorer() -> _BertScorerImpl | None:
    """Return scorer instance if WITH_BERT=1 and model is loadable; else None.

    Failures (missing head, unavailable transformers, etc.) are logged once
    and the function returns None so callers can fall back to AST-only.
    """
    if os.environ.get("WITH_BERT", "0") != "1":
        return None
    try:
        return _BertScorerImpl()
    except Exception as exc:  # noqa: BLE001
        print(f"[bert_scorer] disabled: {exc}")
        return None


def is_enabled() -> bool:
    return os.environ.get("WITH_BERT", "0") == "1"
