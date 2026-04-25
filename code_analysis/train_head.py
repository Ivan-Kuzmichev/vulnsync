"""Stage 4 of BERT_PLAN: train a classification head on cached embeddings.

Architecture (matches dissertation 3.3.2 — adaptive layers + classifier):
    Linear(768 → 256) → Tanh → Dropout(0.3) → Linear(256 → 2)

Binary head: P(BENIGN) vs P(VULNERABLE). The CWE-class itself comes from
the AST detector — the head's job is to provide a robust per-function
vulnerability score that correlates with logs evidence in the integration
layer.

Reads:  data/embeddings.pt
Writes: models/vuln_head.pt — torch dict:
    {"state_dict": ..., "num_classes": 2, "labels": ["BENIGN", "VULNERABLE"],
     "metrics": {...}, "training_args": {...}}

Usage:
    python -m code_analysis.train_head [--epochs 5] [--batch_size 32]
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def _make_head(num_classes: int = 2):
    import torch.nn as nn
    return nn.Sequential(
        nn.Linear(768, 256),
        nn.Tanh(),
        nn.Dropout(0.3),
        nn.Linear(256, num_classes),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_path", default="data/embeddings.pt")
    parser.add_argument("--out", default="models/vuln_head.pt")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch_size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--val_split", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    try:
        import torch
        from torch.utils.data import DataLoader, TensorDataset, random_split
    except ImportError as exc:
        raise SystemExit("Установи: pip install -r requirements-bert.txt") from exc

    torch.manual_seed(args.seed)

    data = torch.load(args.in_path, weights_only=False)
    X = data["X"]
    y = data["y"]
    print(f"Loaded {X.shape[0]} embeddings, dim {X.shape[1]}")
    pos = int(y.sum())
    neg = int(len(y) - pos)
    print(f"  Positives: {pos}, negatives: {neg}")

    dataset = TensorDataset(X, y)
    val_size = int(len(dataset) * args.val_split)
    train_size = len(dataset) - val_size
    train_ds, val_ds = random_split(dataset, [train_size, val_size],
                                    generator=torch.Generator().manual_seed(args.seed))

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False)

    head = _make_head(num_classes=2)
    optim = torch.optim.AdamW(head.parameters(), lr=args.lr, weight_decay=0.01)

    # Class weights for imbalance: CE weighted by inverse frequency
    weights = torch.tensor([
        1.0 / max(neg, 1),
        1.0 / max(pos, 1),
    ])
    weights = weights / weights.sum() * 2.0  # normalize
    print(f"  Class weights: BENIGN={weights[0]:.3f}, VULN={weights[1]:.3f}")
    criterion = torch.nn.CrossEntropyLoss(weight=weights)

    def evaluate(loader):
        head.eval()
        tp = fp = fn = tn = 0
        total_loss = 0.0
        n = 0
        with torch.no_grad():
            for xb, yb in loader:
                logits = head(xb)
                total_loss += criterion(logits, yb).item() * len(yb)
                preds = logits.argmax(dim=-1)
                tp += int(((preds == 1) & (yb == 1)).sum())
                fp += int(((preds == 1) & (yb == 0)).sum())
                fn += int(((preds == 0) & (yb == 1)).sum())
                tn += int(((preds == 0) & (yb == 0)).sum())
                n += len(yb)
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)
        accuracy = (tp + tn) / max(n, 1)
        return {
            "loss": total_loss / max(n, 1),
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        }

    print(f"\nTraining {args.epochs} epochs...")
    best_f1 = -1.0
    best_state = None
    history = []
    start = time.time()

    for epoch in range(args.epochs):
        head.train()
        train_loss = 0.0
        n = 0
        for xb, yb in train_loader:
            optim.zero_grad()
            logits = head(xb)
            loss = criterion(logits, yb)
            loss.backward()
            optim.step()
            train_loss += loss.item() * len(yb)
            n += len(yb)
        train_loss /= max(n, 1)

        val_metrics = evaluate(val_loader)
        history.append({"epoch": epoch + 1, "train_loss": train_loss, **val_metrics})
        print(
            f"  Epoch {epoch+1}/{args.epochs}: "
            f"train_loss={train_loss:.4f}  "
            f"val_loss={val_metrics['loss']:.4f}  "
            f"acc={val_metrics['accuracy']:.3f}  "
            f"P={val_metrics['precision']:.3f}  "
            f"R={val_metrics['recall']:.3f}  "
            f"F1={val_metrics['f1']:.3f}"
        )

        if val_metrics["f1"] > best_f1:
            best_f1 = val_metrics["f1"]
            best_state = {k: v.clone() for k, v in head.state_dict().items()}

    elapsed = time.time() - start
    print(f"\nTraining time: {elapsed:.1f}s. Best val F1: {best_f1:.3f}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": best_state,
            "num_classes": 2,
            "labels": ["BENIGN", "VULNERABLE"],
            "best_f1": best_f1,
            "history": history,
            "training_args": vars(args),
        },
        out_path,
    )
    print(f"Saved head to {out_path}")


if __name__ == "__main__":
    main()
