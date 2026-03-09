# Retraining the TF-IDF Classifier

Retrain the bundled TF-IDF model with your own data or updated public datasets.

## Requirements

```bash
pip install "zugashield[ml-train]"
# Pulls in: datasets, scikit-learn, joblib, scipy
```

## Basic Retraining

```bash
# Train and save to the default location
python -m zugashield.ml.train_tfidf

# Train and save to a custom path
python -m zugashield.ml.train_tfidf --output ./my_model.joblib
```

The script loads 9 public Hugging Face datasets, builds the feature matrix, runs 5-fold cross-validation, and saves the model bundle. Training on a modern CPU takes 5-15 minutes depending on available RAM.

Output:

```
Loading datasets...
  deepset/prompt-injections: 546 samples
  Lakera/gandalf_ignore_instructions: 777 samples
  ...
Raw distribution: 3200 benign, 18000 injection
Final distribution: 9000 benign, 18000 injection
Total: 27000 samples

Building TF-IDF features...
  TF-IDF matrix: (27000, 100000)
Computing heuristic features...
  Heuristic matrix: (27000, 6)
  Combined matrix: (27000, 100006)

Training LogisticRegression (C=50)...
  5-fold CV F1: 0.912 (+/- 0.008)

Model saved to: zugashield/models/tfidf_injection.joblib (4.2 MB)
Model version: 2.0.0, CV F1: 0.912
```

## Benchmarking Configurations

`benchmark_configs.py` tests multiple hyperparameter configurations and measures real detection rates — not just cross-validation F1.

```bash
python -m zugashield.ml.benchmark_configs
```

This tests all configurations defined in `CONFIGS` and produces a summary table:

```
Config                                 Samples  CV F1  Deepset  Gandalf  Combined    FP
R3h: C=50+ng26+100K+cap               27000    0.912  88.7%    100.0%     92.1%   0.0%
```

The scoring formula weights combined recall, deepset recall, and false positive rate:

```python
score = 0.5 * combined_recall + 0.3 * deepset_recall - 2 * fp_rate + 0.2 * gandalf_recall
```

### BenchConfig Fields

| Field | Default | Description |
|-------|---------|-------------|
| `include_spml` | True | Include SPML semantic attack dataset |
| `include_mosscap` | True | Include DEF CON 31 red-team dataset |
| `include_safeguard` | True | Include xTRam1 categorical taxonomy |
| `mosscap_min_level` | 4 | Minimum Mosscap difficulty level (1-8) |
| `mosscap_cap` | 5000 | Max Mosscap samples |
| `spml_cap` | 0 | SPML cap (0 = no limit) |
| `balance_ratio` | 0.0 | Minimum benign:injection ratio padding |
| `use_heuristics` | True | Include heuristic features |
| `ngram_range` | (3, 5) | TF-IDF n-gram range |
| `max_features` | 50000 | TF-IDF vocabulary size |
| `C` | 1.0 | Logistic regression regularization |

The winning configuration that ships as the default (`train_tfidf.py`):

```
ngram_range=(2, 6), max_features=100000, C=50, spml_cap=5000
```

## Custom Training Data

Add your own labeled samples by modifying `_load_original_datasets` or `_load_new_datasets`, or by loading a local dataset:

```python
# In train_tfidf.py, add to _load_original_datasets():
your_data = load_dataset("path/to/your/data", split="train")
for row in your_data:
    texts.append(row["text"])
    labels.append(1 if row["is_injection"] else 0)
```

Labels: `1` = injection/jailbreak, `0` = benign.

## Replacing the Bundled Model

After retraining, copy the output to the user model directory:

```bash
cp ./my_model.joblib ~/.zugashield/models/tfidf_injection.joblib
```

ZugaShield checks `~/.zugashield/models/tfidf_injection.joblib` before the bundled path. Restart your application to pick up the new model.

## Knowledge Distillation (Optional)

Use the ONNX DeBERTa model to pseudo-label unlabeled conversational data, then incorporate it into training:

```bash
# Step 1: Download ONNX model
zugashield-ml download

# Step 2: Generate pseudo-labels (requires: pip install datasets onnxruntime tokenizers)
python -m zugashield.ml.distill --confidence 0.95 --max-samples 10000

# Step 3: Incorporate pseudo_labels.jsonl into your training data
# (modify train_tfidf.py to load the JSONL file)

# Step 4: Retrain
python -m zugashield.ml.train_tfidf --output ~/.zugashield/models/tfidf_injection.joblib
```

Only samples with DeBERTa confidence >= the threshold are kept as pseudo-labels.

Last Updated: 2026-02-17
