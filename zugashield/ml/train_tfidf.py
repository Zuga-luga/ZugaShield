"""
ZugaShield ML — TF-IDF Training Script
========================================

Trains a TF-IDF + Heuristic Features + Logistic Regression classifier
on public prompt injection datasets and saves the model for use by
MLDetectorLayer.

Usage:
    python -m zugashield.ml.train_tfidf
    python -m zugashield.ml.train_tfidf --output ./my_model.joblib

Why ``char_wb`` analyzer:
    Character n-grams within word boundaries survive obfuscation:
    - Leetspeak: "1gnore" shares trigrams with "ignore"
    - Spacing:   "i g n o r e" generates same char-boundary n-grams
    - Unicode:   Cyrillic 'а' in "ignore" → char n-grams still overlap

Datasets (9 total, ~20,000+ samples):
    Original:
    - deepset/prompt-injections (~546 samples, baseline)
    - Lakera/gandalf_ignore_instructions (~777 "ignore" variants)
    - rubend18/ChatGPT-Jailbreak-Prompts (~79 jailbreak prompts)
    - JailbreakBench/JBB-Behaviors (~100 harmful behaviors, NeurIPS 2024)
    - jackhhao/jailbreak-classification (~1044 jailbreak + benign)
    New:
    - reshabhs/SPML_Chatbot_Prompt_Injection (~16K, GPT-4 semantic attacks)
    - Lakera/mosscap_prompt_injection (levels 4-8, cap 5K, DEF CON 31)
    - xTRam1/safe-guard-prompt-injection (~10K, categorical taxonomy)
    - qualifire/prompt-injections-benchmark (~5K, 2025 hard negatives)
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


def _load_original_datasets(load_dataset) -> tuple[list[str], list[int]]:
    """Load the 5 original training datasets."""
    texts: list[str] = []
    labels: list[int] = []

    # Dataset 1: deepset/prompt-injections
    try:
        ds = load_dataset("deepset/prompt-injections", split="train")
        for row in ds:
            texts.append(row["text"])
            labels.append(1 if row["label"] == 1 else 0)
        print(f"  deepset/prompt-injections: {len(ds)} samples")
    except Exception as e:
        print(f"  Warning: Could not load deepset/prompt-injections: {e}")

    # Dataset 2: Lakera/gandalf_ignore_instructions
    try:
        ds = load_dataset("Lakera/gandalf_ignore_instructions", split="train")
        for row in ds:
            text = row.get("text", row.get("prompt", ""))
            if text:
                texts.append(text)
                labels.append(1)  # All are injection attempts
        print(f"  Lakera/gandalf_ignore_instructions: {len(ds)} samples")
    except Exception as e:
        print(f"  Warning: Could not load Lakera/gandalf_ignore_instructions: {e}")

    # Dataset 3: rubend18/ChatGPT-Jailbreak-Prompts
    try:
        ds = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train")
        count = 0
        for row in ds:
            text = row.get("Prompt", "")
            if text and len(text) > 20:
                texts.append(text)
                labels.append(1)
                count += 1
        print(f"  rubend18/ChatGPT-Jailbreak-Prompts: {count} samples")
    except Exception as e:
        print(f"  Warning: Could not load rubend18/ChatGPT-Jailbreak-Prompts: {e}")

    # Dataset 4: JailbreakBench/JBB-Behaviors (NeurIPS 2024 benchmark)
    try:
        ds = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
        count = 0
        for row in ds:
            text = row.get("Goal", "")
            if text and len(text) > 10:
                texts.append(text)
                labels.append(1)
                count += 1
        print(f"  JailbreakBench/JBB-Behaviors (harmful): {count} samples")
    except Exception as e:
        print(f"  Warning: Could not load JailbreakBench/JBB-Behaviors: {e}")

    # Dataset 5: jackhhao/jailbreak-classification (labeled jailbreak + benign)
    try:
        ds = load_dataset("jackhhao/jailbreak-classification", split="train")
        jb_count = 0
        benign_jh = 0
        for row in ds:
            text = row.get("prompt", "")
            label_type = row.get("type", "")
            if text and len(text) > 10:
                texts.append(text)
                if label_type == "jailbreak":
                    labels.append(1)
                    jb_count += 1
                else:
                    labels.append(0)
                    benign_jh += 1
        print(f"  jackhhao/jailbreak-classification: {jb_count} jailbreak + {benign_jh} benign")
    except Exception as e:
        print(f"  Warning: Could not load jackhhao/jailbreak-classification: {e}")

    return texts, labels


def _load_new_datasets(load_dataset) -> tuple[list[str], list[int]]:
    """Load the 4 new training datasets for improved semantic coverage."""
    texts: list[str] = []
    labels: list[int] = []

    # Dataset 6: reshabhs/SPML_Chatbot_Prompt_Injection (~16K semantic attacks)
    # Schema: "User Prompt" (text), "Prompt injection" (0/1 label)
    # Capped at 5K to prevent dominating the training set (tuned via benchmark)
    spml_cap = 5000
    try:
        ds = load_dataset("reshabhs/SPML_Chatbot_Prompt_Injection", split="train")
        count = 0
        benign_count = 0
        for row in ds:
            if spml_cap and (count + benign_count) >= spml_cap:
                break
            text = row.get("User Prompt", "")
            label = row.get("Prompt injection", None)
            if text and len(text) > 10:
                texts.append(text)
                if label == 1:
                    labels.append(1)
                    count += 1
                else:
                    labels.append(0)
                    benign_count += 1
        print(f"  reshabhs/SPML_Chatbot_Prompt_Injection: {count} injection + {benign_count} benign (cap {spml_cap})")
    except Exception as e:
        print(f"  Warning: Could not load reshabhs/SPML_Chatbot_Prompt_Injection: {e}")

    # Dataset 7: Lakera/mosscap_prompt_injection (DEF CON 31 red-team)
    # Schema: "level" (str like "Level 8"), "prompt" (text)
    # Take levels 4-8 only (harder attacks), cap at 5,000 samples
    try:
        ds = load_dataset("Lakera/mosscap_prompt_injection", split="train")
        count = 0
        max_mosscap = 5000
        for row in ds:
            if count >= max_mosscap:
                break
            level_str = row.get("level", "")
            try:
                level_num = int(level_str.split()[-1]) if level_str else 0
            except (ValueError, IndexError):
                level_num = 0
            if level_num < 4:
                continue
            text = row.get("prompt", "")
            if text and len(text) > 10:
                texts.append(text)
                labels.append(1)  # All are injection attempts
                count += 1
        print(f"  Lakera/mosscap_prompt_injection (L4-8, cap {max_mosscap}): {count} samples")
    except Exception as e:
        print(f"  Warning: Could not load Lakera/mosscap_prompt_injection: {e}")

    # Dataset 8: xTRam1/safe-guard-prompt-injection (~10K categorical taxonomy)
    try:
        ds = load_dataset("xTRam1/safe-guard-prompt-injection", split="train")
        count = 0
        benign_count = 0
        for row in ds:
            text = row.get("text", row.get("prompt", ""))
            label = row.get("label", None)
            if text and len(text) > 10:
                texts.append(text)
                if label == 1:
                    labels.append(1)
                    count += 1
                else:
                    labels.append(0)
                    benign_count += 1
        print(f"  xTRam1/safe-guard-prompt-injection: {count} injection + {benign_count} benign")
    except Exception as e:
        print(f"  Warning: Could not load xTRam1/safe-guard-prompt-injection: {e}")

    # Dataset 9: qualifire/prompt-injections-benchmark (~5K, 2025 hard negatives)
    try:
        ds = load_dataset("qualifire/prompt-injections-benchmark", split="train")
        count = 0
        benign_count = 0
        for row in ds:
            text = row.get("text", row.get("prompt", ""))
            label = row.get("label", None)
            if text and len(text) > 10:
                texts.append(text)
                if label == 1:
                    labels.append(1)
                    count += 1
                else:
                    labels.append(0)
                    benign_count += 1
        print(f"  qualifire/prompt-injections-benchmark: {count} injection + {benign_count} benign")
    except Exception as e:
        print(f"  Warning: Could not load qualifire/prompt-injections-benchmark: {e}")

    return texts, labels


def train(output_path: str = "") -> None:
    """Train TF-IDF + heuristic features model and save to disk."""
    try:
        from datasets import load_dataset
    except ImportError:
        print("Error: 'datasets' package required. Install: pip install zugashield[ml-train]")
        sys.exit(1)

    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import cross_val_score
    import joblib
    import numpy as np
    from scipy.sparse import hstack, csr_matrix

    from zugashield.ml.features import compute_heuristic_features, NUM_HEURISTIC_FEATURES

    print("Loading datasets...")

    # Load original + new datasets
    texts_orig, labels_orig = _load_original_datasets(load_dataset)
    texts_new, labels_new = _load_new_datasets(load_dataset)

    texts = texts_orig + texts_new
    labels = labels_orig + labels_new

    # Track which datasets were loaded for metadata
    dataset_names = [
        "deepset", "gandalf", "rubend18", "jailbreakbench", "jackhhao",
        "spml", "mosscap", "safe-guard", "qualifire",
    ]

    # Add benign samples if imbalanced
    benign_count = sum(1 for l in labels if l == 0)
    injection_count = sum(1 for l in labels if l == 1)
    print(f"\nRaw distribution: {benign_count} benign, {injection_count} injection")

    if benign_count < injection_count * 0.3:
        benign_samples = [
            "What is the weather today?",
            "Can you help me write a Python function?",
            "Tell me about machine learning",
            "How do I sort a list in JavaScript?",
            "What are the best restaurants nearby?",
            "Explain quantum computing",
            "Write a haiku about spring",
            "What is the capital of France?",
            "How do I install numpy?",
            "Summarize this article for me",
            "What time is the meeting?",
            "How do I create a React component?",
            "Explain the difference between TCP and UDP",
            "What are design patterns in software engineering?",
            "How do I deploy to AWS?",
            "Write a SQL query to find duplicates",
            "What is Docker and how do I use it?",
            "Explain REST API best practices",
            "How does garbage collection work?",
            "What is the Big O notation for binary search?",
        ]
        while benign_count < injection_count * 0.5:
            for s in benign_samples:
                texts.append(s)
                labels.append(0)
                benign_count += 1
                if benign_count >= injection_count * 0.5:
                    break

    final_benign = sum(1 for l in labels if l == 0)
    final_injection = sum(1 for l in labels if l == 1)
    print(f"Final distribution: {final_benign} benign, {final_injection} injection")
    print(f"Total: {len(texts)} samples")

    # Build TF-IDF vectorizer (step 1 of 2-stage pipeline)
    # Tuned via 3-round benchmark: ngram_range=(2,6) + 100K features won
    print("\nBuilding TF-IDF features...")
    tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 6),
        max_features=100000,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    X_tfidf = tfidf.fit_transform(texts)
    print(f"  TF-IDF matrix: {X_tfidf.shape}")

    # Compute heuristic features
    print("Computing heuristic features...")
    heuristic_list = [compute_heuristic_features(t) for t in texts]
    X_heuristic = csr_matrix(np.array(heuristic_list, dtype=np.float64))
    print(f"  Heuristic matrix: {X_heuristic.shape}")

    # Combine: [TF-IDF sparse | heuristic dense->sparse]
    X_combined = hstack([X_tfidf, X_heuristic], format="csr")
    print(f"  Combined matrix: {X_combined.shape}")

    # Train classifier
    # C=50 tuned via 3-round benchmark (deepset 88.7%, gandalf 100%, 0% FP)
    print("\nTraining LogisticRegression (C=50)...")
    clf = LogisticRegression(
        C=50.0,
        max_iter=1000,
        solver="lbfgs",
        class_weight="balanced",
    )

    labels_arr = np.array(labels)

    # Cross-validation on combined features
    scores = cross_val_score(clf, X_combined, labels_arr, cv=5, scoring="f1")
    print(f"  5-fold CV F1: {scores.mean():.3f} (+/- {scores.std():.3f})")

    # Train on full dataset
    clf.fit(X_combined, labels_arr)

    # Bundle everything into a saveable dict
    # We can't use sklearn Pipeline since heuristic features are computed separately
    model_bundle = {
        "tfidf": tfidf,
        "clf": clf,
        "has_heuristic_features": True,
        "n_heuristic_features": NUM_HEURISTIC_FEATURES,
        "__zugashield_meta__": {
            "version": "2.0.0",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "samples": len(texts),
            "cv_f1": float(scores.mean()),
            "datasets": dataset_names,
        },
    }

    # Save
    if not output_path:
        output_path = str(Path(__file__).parent.parent / "models" / "tfidf_injection.joblib")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_bundle, output_path)
    size_mb = Path(output_path).stat().st_size / (1024 * 1024)
    print(f"\nModel saved to: {output_path} ({size_mb:.1f} MB)")
    print(f"Model version: 2.0.0, CV F1: {scores.mean():.3f}")
    print("This file will be bundled with the pip package.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train TF-IDF injection classifier")
    parser.add_argument(
        "--output", "-o",
        default="",
        help="Output path for model file (default: zugashield/models/tfidf_injection.joblib)",
    )
    args = parser.parse_args()
    train(args.output)


if __name__ == "__main__":
    main()
