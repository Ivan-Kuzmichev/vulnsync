"""Stage 3 of BERT_PLAN: compute and cache GraphCodeBERT embeddings.

This is the slow stage (~10–15 min on M-series Mac with MPS, longer on CPU).
After it completes, training the head is fast (~1 min) and can be repeated
without recomputing embeddings.

Reads:  data/dataset.jsonl
Writes: data/embeddings.pt — a torch dict:
    {"X": Tensor[N, 768], "y": Tensor[N], "cwe": List[str], "source": List[str]}

Usage:
    python -m code_analysis.embed_dataset [--max_length 512] [--batch_size 4]
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def _device(prefer: str | None = None):
    import torch
    if prefer == "cpu":
        return torch.device("cpu")
    if torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_path", default="data/dataset.jsonl")
    parser.add_argument("--out", default="data/embeddings.pt")
    parser.add_argument("--max_length", type=int, default=512)
    parser.add_argument("--batch_size", type=int, default=4,
                        help="Increase on GPU; on CPU/MPS keep small")
    parser.add_argument("--device", choices=["auto", "cpu", "cuda", "mps"], default="auto")
    args = parser.parse_args()

    try:
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("Установи: pip install -r requirements-bert.txt") from exc

    in_path = Path(args.in_path)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    records = [json.loads(line) for line in in_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    print(f"Loaded {len(records)} records from {in_path}")

    device = _device(args.device if args.device != "auto" else None)
    print(f"Using device: {device}")

    print("Loading microsoft/graphcodebert-base ...")
    tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
    model = AutoModel.from_pretrained("microsoft/graphcodebert-base").to(device)
    model.eval()
    for p in model.parameters():
        p.requires_grad = False

    embeddings: list[torch.Tensor] = []
    labels: list[int] = []
    cwes: list[str] = []
    sources: list[str] = []

    start = time.time()
    bs = args.batch_size
    total = len(records)
    for i in range(0, total, bs):
        batch = records[i : i + bs]
        codes = [r["code"] for r in batch]
        enc = tokenizer(
            codes,
            padding=True,
            truncation=True,
            max_length=args.max_length,
            return_tensors="pt",
        ).to(device)
        with torch.no_grad():
            out = model(**enc)
        cls = out.last_hidden_state[:, 0, :].cpu()  # [batch, 768]
        embeddings.append(cls)
        labels.extend(int(r["label"]) for r in batch)
        cwes.extend(r["cwe"] for r in batch)
        sources.extend(r["source"] for r in batch)

        done = min(i + bs, total)
        if done % 100 == 0 or done == total:
            elapsed = time.time() - start
            rate = done / max(elapsed, 1e-6)
            eta = (total - done) / max(rate, 1e-6)
            print(f"  [{done}/{total}] {rate:.1f} samples/s, ETA {eta:.0f}s")

    X = torch.cat(embeddings, dim=0)
    y = torch.tensor(labels, dtype=torch.long)

    torch.save(
        {"X": X, "y": y, "cwe": cwes, "source": sources},
        out_path,
    )
    print(f"\nDone. Saved {X.shape[0]} embeddings of dim {X.shape[1]} to {out_path}")
    print(f"Total time: {time.time() - start:.0f}s")


if __name__ == "__main__":
    main()
