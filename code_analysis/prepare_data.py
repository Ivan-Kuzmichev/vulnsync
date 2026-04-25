"""Stage 2 of BERT_PLAN: prepare the training dataset.

Combines:
  - Devign (CodeXGLUE defect-detection): C/C++ functions with binary labels
  - Synthetic Python examples from `synthetic.py` covering 7 CWE classes

Output: data/dataset.jsonl, one JSON per line:
    {"code": "...", "label": 0 | 1, "cwe": "...", "source": "devign" | "synthetic-py"}

Usage:
    python -m code_analysis.prepare_data [--devign-samples 1000]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .synthetic import generate as generate_synthetic


def _load_devign(num_samples: int):
    """Load Devign via Hugging Face datasets. Returns iterable of dicts."""
    try:
        from datasets import load_dataset
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "Установи зависимости: pip install -r requirements-bert.txt"
        ) from exc

    print(f"Loading Devign (CodeXGLUE defect-detection)...")
    ds = load_dataset("code_x_glue_cc_defect_detection", split="train")
    ds = ds.shuffle(seed=42)
    if num_samples > 0:
        ds = ds.select(range(min(num_samples, len(ds))))
    print(f"  Devign samples: {len(ds)}")
    return ds


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--devign-samples", type=int, default=1000,
                        help="Cap on Devign samples (0 = use all)")
    parser.add_argument("--synthetic-per-class", type=int, default=80,
                        help="Synthetic samples per CWE per polarity")
    parser.add_argument("--out", type=str, default="data/dataset.jsonl")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with out_path.open("w", encoding="utf-8") as f:
        # Devign
        ds = _load_devign(args.devign_samples)
        for row in ds:
            rec = {
                "code": row["func"],
                "label": int(row["target"]),
                "cwe": "CWE-OTHER" if row["target"] == 1 else "BENIGN",
                "source": "devign",
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            written += 1

        # Synthetic Python
        synth = generate_synthetic(samples_per_class=args.synthetic_per_class)
        print(f"  Synthetic Python samples: {len(synth)}")
        for s in synth:
            rec = {"code": s.code, "label": s.label, "cwe": s.cwe, "source": s.source}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            written += 1

    print(f"\nDone. {written} records → {out_path}")


if __name__ == "__main__":
    main()
