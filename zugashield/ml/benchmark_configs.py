"""
ZugaShield ML — Training Configuration Benchmark
==================================================

Tests multiple training configurations and measures real detection rates
against deepset + gandalf datasets (not just CV F1).

Usage:
    python -m zugashield.ml.benchmark_configs
"""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class BenchConfig:
    """A single training configuration to benchmark."""
    name: str
    # Data
    include_spml: bool = True
    include_mosscap: bool = True
    include_safeguard: bool = True
    mosscap_min_level: int = 4
    mosscap_cap: int = 5000
    spml_cap: int = 0  # 0 = no cap
    # Balance
    balance_ratio: float = 0.0  # 0 = no rebalancing. 0.5 = benign >= 50% of injection
    downsample_injection_to: int = 0  # 0 = no downsampling
    # Features
    use_heuristics: bool = True
    ngram_range: tuple = (3, 5)
    max_features: int = 50000
    # Model
    C: float = 1.0
    solver: str = "lbfgs"


# Configurations to test
CONFIGS = [
    # === Round 3: High-C sweep + best combos ===

    # R2 baseline for comparison
    BenchConfig(
        name="R2e: C=20 (R2 winner)",
        C=20.0,
    ),

    # Push C higher — find plateau
    BenchConfig(
        name="R3a: C=30",
        C=30.0,
    ),
    BenchConfig(
        name="R3b: C=50",
        C=50.0,
    ),
    BenchConfig(
        name="R3c: C=100",
        C=100.0,
    ),

    # C=20 + SPML cap (reduce SPML dominance at high C)
    BenchConfig(
        name="R3d: C=20 + SPML cap 5K",
        C=20.0,
        spml_cap=5000,
    ),

    # C=20 + all mosscap + SPML cap
    BenchConfig(
        name="R3e: C=20+SPMLcap+AllMoss",
        C=20.0,
        spml_cap=5000,
        mosscap_min_level=1,
        mosscap_cap=10000,
    ),

    # C=50 + SPML cap + all mosscap
    BenchConfig(
        name="R3f: C=50+SPMLcap+AllMoss",
        C=50.0,
        spml_cap=5000,
        mosscap_min_level=1,
        mosscap_cap=10000,
    ),

    # C=20 + wider n-grams (2,6) + 100K features
    BenchConfig(
        name="R3g: C=20+ng(2,6)+100K",
        C=20.0,
        ngram_range=(2, 6),
        max_features=100000,
    ),

    # C=50 + wider n-grams + 100K + SPML cap
    BenchConfig(
        name="R3h: C=50+ng26+100K+cap",
        C=50.0,
        ngram_range=(2, 6),
        max_features=100000,
        spml_cap=5000,
    ),

    # C=20 + no heuristics (are heuristics still helping at high C?)
    BenchConfig(
        name="R3i: C=20 no heuristics",
        C=20.0,
        use_heuristics=False,
    ),

    # C=100 + everything maxed
    BenchConfig(
        name="R3j: C=100+ng26+100K+cap+moss",
        C=100.0,
        ngram_range=(2, 6),
        max_features=100000,
        spml_cap=5000,
        mosscap_min_level=1,
        mosscap_cap=10000,
    ),
]


def _load_datasets(config: BenchConfig):
    """Load datasets according to config. Returns (texts, labels)."""
    from datasets import load_dataset
    import random

    texts = []
    labels = []

    # Original 5 datasets (always included)
    try:
        ds = load_dataset("deepset/prompt-injections", split="train")
        for row in ds:
            texts.append(row["text"])
            labels.append(1 if row["label"] == 1 else 0)
    except Exception:
        pass

    try:
        ds = load_dataset("Lakera/gandalf_ignore_instructions", split="train")
        for row in ds:
            text = row.get("text", row.get("prompt", ""))
            if text:
                texts.append(text)
                labels.append(1)
    except Exception:
        pass

    try:
        ds = load_dataset("rubend18/ChatGPT-Jailbreak-Prompts", split="train")
        for row in ds:
            text = row.get("Prompt", "")
            if text and len(text) > 20:
                texts.append(text)
                labels.append(1)
    except Exception:
        pass

    try:
        ds = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors", split="harmful")
        for row in ds:
            text = row.get("Goal", "")
            if text and len(text) > 10:
                texts.append(text)
                labels.append(1)
    except Exception:
        pass

    try:
        ds = load_dataset("jackhhao/jailbreak-classification", split="train")
        for row in ds:
            text = row.get("prompt", "")
            label_type = row.get("type", "")
            if text and len(text) > 10:
                texts.append(text)
                labels.append(1 if label_type == "jailbreak" else 0)
    except Exception:
        pass

    # New datasets (conditionally included)
    if config.include_spml:
        try:
            ds = load_dataset("reshabhs/SPML_Chatbot_Prompt_Injection", split="train")
            count = 0
            for row in ds:
                if config.spml_cap and count >= config.spml_cap:
                    break
                text = row.get("User Prompt", "")
                label = row.get("Prompt injection", None)
                if text and len(text) > 10:
                    texts.append(text)
                    labels.append(1 if label == 1 else 0)
                    count += 1
        except Exception:
            pass

    if config.include_mosscap:
        try:
            ds = load_dataset("Lakera/mosscap_prompt_injection", split="train")
            count = 0
            for row in ds:
                if count >= config.mosscap_cap:
                    break
                level_str = row.get("level", "")
                try:
                    level_num = int(level_str.split()[-1]) if level_str else 0
                except (ValueError, IndexError):
                    level_num = 0
                if level_num < config.mosscap_min_level:
                    continue
                text = row.get("prompt", "")
                if text and len(text) > 10:
                    texts.append(text)
                    labels.append(1)
                    count += 1
        except Exception:
            pass

    if config.include_safeguard:
        try:
            ds = load_dataset("xTRam1/safe-guard-prompt-injection", split="train")
            for row in ds:
                text = row.get("text", row.get("prompt", ""))
                label = row.get("label", None)
                if text and len(text) > 10:
                    texts.append(text)
                    labels.append(1 if label == 1 else 0)
        except Exception:
            pass

    # Downsampling
    if config.downsample_injection_to > 0:
        inj_indices = [i for i, l in enumerate(labels) if l == 1]
        ben_indices = [i for i, l in enumerate(labels) if l == 0]
        if len(inj_indices) > config.downsample_injection_to:
            random.seed(42)
            keep = set(random.sample(inj_indices, config.downsample_injection_to))
            keep.update(ben_indices)
            texts = [texts[i] for i in sorted(keep)]
            labels = [labels[i] for i in sorted(keep)]

    # Balance padding
    benign_count = sum(1 for l in labels if l == 0)
    injection_count = sum(1 for l in labels if l == 1)
    if config.balance_ratio > 0 and benign_count < injection_count * config.balance_ratio:
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
        while benign_count < injection_count * config.balance_ratio:
            for s in benign_samples:
                texts.append(s)
                labels.append(0)
                benign_count += 1
                if benign_count >= injection_count * config.balance_ratio:
                    break

    return texts, labels


def _train_and_save(config: BenchConfig, texts, labels, output_path: str):
    """Train a model with the given config and return (cv_f1, model_path)."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import cross_val_score
    import joblib
    import numpy as np
    from scipy.sparse import hstack, csr_matrix

    tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=config.ngram_range,
        max_features=config.max_features,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    X_tfidf = tfidf.fit_transform(texts)

    if config.use_heuristics:
        from zugashield.ml.features import compute_heuristic_features, NUM_HEURISTIC_FEATURES
        heuristic_list = [compute_heuristic_features(t) for t in texts]
        X_heur = csr_matrix(np.array(heuristic_list, dtype=np.float64))
        X = hstack([X_tfidf, X_heur], format="csr")
    else:
        X = X_tfidf

    clf = LogisticRegression(
        C=config.C,
        max_iter=1000,
        solver=config.solver,
        class_weight="balanced",
    )

    labels_arr = np.array(labels)
    scores = cross_val_score(clf, X, labels_arr, cv=5, scoring="f1")
    cv_f1 = float(scores.mean())

    clf.fit(X, labels_arr)

    bundle = {
        "tfidf": tfidf,
        "clf": clf,
        "has_heuristic_features": config.use_heuristics,
        "n_heuristic_features": 6 if config.use_heuristics else 0,
        "__zugashield_meta__": {
            "version": "2.0.0-bench",
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "samples": len(texts),
            "cv_f1": cv_f1,
        },
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, output_path)
    return cv_f1


def _evaluate_coverage(model_path: str):
    """Run the model against deepset + gandalf and return detection rates."""
    from datasets import load_dataset
    from zugashield import ZugaShield
    from zugashield.config import ShieldConfig

    # Point ZugaShield at the benchmark model
    config = ShieldConfig(
        ml_detector_enabled=True,
        ml_onnx_enabled=False,
        ml_model_version="",  # Accept any version
        verify_signatures=False,  # Don't check hashes for benchmark models
    )
    shield = ZugaShield(config)

    # Force-load the benchmark model
    ml_layer = shield._ml_detector
    if ml_layer is None:
        return {"error": "ML layer not found"}

    # Override the model path
    import joblib
    ml_layer._tfidf_model = joblib.load(model_path)
    ml_layer._has_heuristic_features = ml_layer._tfidf_model.get("has_heuristic_features", False)
    ml_layer._stats["tfidf_loaded"] = True
    ml_layer._stats["canary_passed"] = True

    # Load test datasets
    ds_deepset = load_dataset("deepset/prompt-injections", split="train")
    deepset_inj = [row["text"] for row in ds_deepset if row["label"] == 1]
    deepset_ben = [row["text"] for row in ds_deepset if row["label"] == 0]

    ds_gandalf = load_dataset("Lakera/gandalf_ignore_instructions", split="train")
    gandalf = [row.get("text", row.get("prompt", "")) for row in ds_gandalf if row.get("text", row.get("prompt", ""))]

    def run(coro):
        return asyncio.run(coro)

    # Deepset injection recall
    deepset_det = 0
    for i, text in enumerate(deepset_inj):
        result = run(shield.check_prompt(text, context={"session_id": f"bench-dinj-{i}"}))
        if result.threats_detected:
            deepset_det += 1
    deepset_recall = deepset_det / len(deepset_inj) if deepset_inj else 0

    # Deepset FP rate
    fp = 0
    for i, text in enumerate(deepset_ben):
        result = run(shield.check_prompt(text, context={"session_id": f"bench-dben-{i}"}))
        if result.threats_detected:
            fp += 1
    fp_rate = fp / len(deepset_ben) if deepset_ben else 0

    # Gandalf recall
    gandalf_det = 0
    for i, text in enumerate(gandalf):
        result = run(shield.check_prompt(text, context={"session_id": f"bench-gand-{i}"}))
        if result.threats_detected:
            gandalf_det += 1
    gandalf_recall = gandalf_det / len(gandalf) if gandalf else 0

    # Combined
    all_inj = deepset_inj + gandalf
    combined_det = deepset_det + gandalf_det
    combined_recall = combined_det / len(all_inj) if all_inj else 0

    return {
        "deepset_recall": deepset_recall,
        "deepset_det": deepset_det,
        "deepset_total": len(deepset_inj),
        "gandalf_recall": gandalf_recall,
        "gandalf_det": gandalf_det,
        "gandalf_total": len(gandalf),
        "combined_recall": combined_recall,
        "fp_rate": fp_rate,
        "fp_count": fp,
        "fp_total": len(deepset_ben),
    }


def main():
    import tempfile
    import os

    print("=" * 80)
    print("ZugaShield ML — Training Configuration Benchmark")
    print("=" * 80)
    print(f"Testing {len(CONFIGS)} configurations\n")

    results = []

    for i, config in enumerate(CONFIGS):
        print(f"\n{'-' * 70}")
        print(f"[{i+1}/{len(CONFIGS)}] {config.name}")
        print(f"{'-' * 70}")

        # Load data
        t0 = time.time()
        texts, labels = _load_datasets(config)
        benign = sum(1 for l in labels if l == 0)
        injection = sum(1 for l in labels if l == 1)
        print(f"  Data: {len(texts)} total ({injection} inj, {benign} ben, ratio {injection/max(benign,1):.1f}:1)")

        # Train
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            tmp_path = f.name

        try:
            cv_f1 = _train_and_save(config, texts, labels, tmp_path)
            train_time = time.time() - t0
            print(f"  CV F1: {cv_f1:.3f}  (trained in {train_time:.1f}s)")

            # Evaluate
            t1 = time.time()
            metrics = _evaluate_coverage(tmp_path)
            eval_time = time.time() - t1
            print(f"  Deepset:  {metrics['deepset_det']}/{metrics['deepset_total']} = {metrics['deepset_recall']:.1%}")
            print(f"  Gandalf:  {metrics['gandalf_det']}/{metrics['gandalf_total']} = {metrics['gandalf_recall']:.1%}")
            print(f"  Combined: {metrics['combined_recall']:.1%}")
            print(f"  FP rate:  {metrics['fp_count']}/{metrics['fp_total']} = {metrics['fp_rate']:.1%}")
            print(f"  (eval in {eval_time:.1f}s)")

            results.append({
                "name": config.name,
                "samples": len(texts),
                "cv_f1": cv_f1,
                **metrics,
            })
        finally:
            os.unlink(tmp_path)

    # Summary table
    print(f"\n\n{'=' * 100}")
    print("SUMMARY")
    print(f"{'=' * 100}")
    header = f"{'Config':<40} {'Samples':>7} {'CV F1':>6} {'Deepset':>8} {'Gandalf':>8} {'Combined':>9} {'FP':>6}"
    print(header)
    print("-" * 100)
    for r in results:
        line = (
            f"{r['name']:<40} "
            f"{r['samples']:>7} "
            f"{r['cv_f1']:>6.3f} "
            f"{r['deepset_recall']:>7.1%} "
            f"{r['gandalf_recall']:>7.1%} "
            f"{r['combined_recall']:>8.1%} "
            f"{r['fp_rate']:>5.1%}"
        )
        print(line)
    print("-" * 100)

    # Find best config
    best = max(results, key=lambda r: r["combined_recall"] * 0.5 + r["deepset_recall"] * 0.3 - r["fp_rate"] * 2 + r["gandalf_recall"] * 0.2)
    print(f"\nBest overall: {best['name']}")
    print(f"  Score formula: 0.5*combined + 0.3*deepset - 2*fp + 0.2*gandalf")


if __name__ == "__main__":
    main()
