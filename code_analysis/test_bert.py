"""Stage 5 of BERT_PLAN: smoke-test BERT inference on demo samples.

Requires:
  - data/embeddings.pt (from prepare_data.py + embed_dataset.py)
  - models/vuln_head.pt (from train_head.py)
  - WITH_BERT=1 env var or pass --force
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .bert_scorer import _BertScorerImpl, _DEFAULT_HEAD


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples-dir", default="samples")
    parser.add_argument("--head", default=str(_DEFAULT_HEAD))
    args = parser.parse_args()

    if not Path(args.head).exists():
        raise SystemExit(f"Head not found at {args.head}. Train it first.")

    print(f"Loading scorer (head: {args.head})...")
    scorer = _BertScorerImpl(head_path=Path(args.head))
    print(f"Scorer ready on {scorer.device}. Best val F1: {scorer.head_metrics['best_f1']}\n")

    samples_dir = Path(args.samples_dir)
    for fname in ["vulnerable_app.py", "clean_app.py", "mixed_app.py", "admin_panel.py"]:
        path = samples_dir / fname
        if not path.exists():
            continue
        print(f"=== {fname} ===")
        scores = scorer.score_functions(path.read_text(encoding="utf-8"))
        for s in scores:
            verdict = "VULN" if s.p_vulnerable >= 0.5 else "safe"
            print(f"  [{verdict:4}] {s.function:20} line {s.line:3}  P_vuln={s.p_vulnerable:.3f}")
        if scores:
            avg = sum(s.p_vulnerable for s in scores) / len(scores)
            print(f"  Average P_vuln: {avg:.3f}\n")


if __name__ == "__main__":
    main()
