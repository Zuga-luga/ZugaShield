"""
ZugaShield ML — Knowledge Distillation (Teacher → Student)
============================================================

Uses the ONNX DeBERTa model as a teacher to pseudo-label a large
unlabeled corpus, then adds those labels to TF-IDF training data.

This is a **development script** — not shipped in the package.
Run manually to improve the TF-IDF model using DeBERTa's semantic
understanding.

Usage:
    python -m zugashield.ml.distill
    python -m zugashield.ml.distill --confidence 0.95 --max-samples 10000

Steps:
    1. Load unlabeled conversational samples (benign + synthetic injection)
    2. Run DeBERTa ONNX over all samples
    3. Keep predictions where confidence > threshold
    4. Save pseudo-labeled dataset for use in train_tfidf.py

Requirements:
    pip install zugashield[ml] datasets
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def distill(
    model_dir: str = "~/.zugashield/models",
    confidence_threshold: float = 0.95,
    max_samples: int = 10000,
    output_path: str = "",
) -> None:
    """
    Run knowledge distillation: DeBERTa teacher → pseudo-labeled dataset.

    Args:
        model_dir: Path to ONNX model directory.
        confidence_threshold: Minimum DeBERTa confidence to keep a label.
        max_samples: Maximum unlabeled samples to process.
        output_path: Output JSONL path for pseudo-labeled data.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        print("Error: 'datasets' package required. Install: pip install datasets")
        sys.exit(1)

    try:
        import onnxruntime as ort
        import numpy as np
        from tokenizers import Tokenizer
    except ImportError:
        print("Error: ONNX dependencies required. Install: pip install onnxruntime tokenizers")
        sys.exit(1)

    import os

    model_dir_path = Path(os.path.expanduser(model_dir))
    onnx_path = model_dir_path / "deberta_injection.onnx"
    tokenizer_path = model_dir_path / "tokenizer.json"

    if not onnx_path.exists() or not tokenizer_path.exists():
        print(f"Error: ONNX model not found at {model_dir_path}")
        print("Run: zugashield-ml download")
        sys.exit(1)

    # Load teacher model
    print("Loading DeBERTa teacher model...")
    sess_opts = ort.SessionOptions()
    sess_opts.intra_op_num_threads = 2
    session = ort.InferenceSession(
        str(onnx_path), sess_options=sess_opts,
        providers=["CPUExecutionProvider"],
    )
    tokenizer = Tokenizer.from_file(str(tokenizer_path))
    tokenizer.enable_truncation(max_length=512)
    tokenizer.enable_padding(length=512)

    def predict(text: str) -> tuple[int, float]:
        """Returns (label, confidence)."""
        encoding = tokenizer.encode(text)
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)
        outputs = session.run(None, {"input_ids": input_ids, "attention_mask": attention_mask})
        logits = outputs[0][0]
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / exp_logits.sum()
        label = int(np.argmax(probs))
        confidence = float(probs[label])
        return label, confidence

    # Step 1: Collect unlabeled samples
    print(f"Loading unlabeled samples (max {max_samples})...")
    unlabeled: list[str] = []

    # Benign conversational samples
    try:
        ds = load_dataset("alespalla/chatbot_instruction_prompts", split="train")
        for row in ds:
            if len(unlabeled) >= max_samples:
                break
            text = row.get("prompt", "")
            if text and 10 < len(text) < 2000:
                unlabeled.append(text)
        print(f"  Loaded {len(unlabeled)} conversational samples")
    except Exception as e:
        print(f"  Warning: Could not load chatbot_instruction_prompts: {e}")

    if not unlabeled:
        print("Error: No unlabeled samples loaded. Cannot proceed.")
        sys.exit(1)

    # Step 2: Pseudo-label with DeBERTa
    print(f"Pseudo-labeling {len(unlabeled)} samples with DeBERTa...")
    pseudo_labeled: list[dict] = []
    kept = 0
    skipped = 0

    for i, text in enumerate(unlabeled):
        if (i + 1) % 500 == 0:
            print(f"  Processed {i + 1}/{len(unlabeled)} ({kept} kept, {skipped} low-confidence)")

        try:
            label, confidence = predict(text)
            if confidence >= confidence_threshold:
                pseudo_labeled.append({
                    "text": text,
                    "label": label,
                    "confidence": round(confidence, 4),
                    "source": "distillation",
                })
                kept += 1
            else:
                skipped += 1
        except Exception:
            skipped += 1

    print(f"\nDistillation complete:")
    print(f"  Total processed: {len(unlabeled)}")
    print(f"  Kept (confidence >= {confidence_threshold}): {kept}")
    print(f"  Skipped (low confidence): {skipped}")

    benign = sum(1 for p in pseudo_labeled if p["label"] == 0)
    injection = sum(1 for p in pseudo_labeled if p["label"] == 1)
    print(f"  Benign: {benign}, Injection: {injection}")

    # Step 3: Save pseudo-labeled dataset
    if not output_path:
        output_path = str(Path(__file__).parent / "pseudo_labels.jsonl")

    with open(output_path, "w", encoding="utf-8") as f:
        for item in pseudo_labeled:
            f.write(json.dumps(item) + "\n")

    print(f"\nPseudo-labeled data saved to: {output_path}")
    print("To use in training, add --pseudo-labels flag to train_tfidf.py (future feature)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Knowledge distillation: DeBERTa → TF-IDF pseudo-labels",
    )
    parser.add_argument(
        "--model-dir",
        default="~/.zugashield/models",
        help="ONNX model directory",
    )
    parser.add_argument(
        "--confidence",
        type=float,
        default=0.95,
        help="Minimum confidence threshold (default: 0.95)",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=10000,
        help="Max unlabeled samples to process (default: 10000)",
    )
    parser.add_argument(
        "--output", "-o",
        default="",
        help="Output JSONL path",
    )
    args = parser.parse_args()
    distill(args.model_dir, args.confidence, args.max_samples, args.output)


if __name__ == "__main__":
    main()
