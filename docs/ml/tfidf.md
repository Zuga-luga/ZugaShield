# TF-IDF Classifier

ZugaShield bundles a TF-IDF + Heuristic Features + Logistic Regression classifier for prompt injection detection. It runs entirely offline (no network, no GPU) and is used as the first tier of the ML detection layer.

## Architecture

The model is a two-stage pipeline:

1. **TF-IDF Vectorizer** — character n-gram features from text
2. **Heuristic Features** — 6 semantically-targeted features (see below)
3. **Logistic Regression** — combines both feature sets

The feature matrix is built with `scipy.sparse.hstack([X_tfidf, X_heuristic])`.

### TF-IDF Configuration

```python
TfidfVectorizer(
    analyzer="char_wb",     # Character n-grams within word boundaries
    ngram_range=(2, 6),     # 2- to 6-character n-grams
    max_features=100000,    # 100K features
    sublinear_tf=True,      # Log normalization
    strip_accents="unicode",
)
```

`char_wb` (character n-grams within word boundaries) is used because it survives common obfuscation:

- Leetspeak: `"1gnore"` shares trigrams with `"ignore"`
- Spaced letters: `"i g n o r e"` produces the same character boundary n-grams
- Unicode substitution: Cyrillic `а` in `"ignore"` still overlaps

### Classifier Configuration

```python
LogisticRegression(
    C=50.0,
    max_iter=1000,
    solver="lbfgs",
    class_weight="balanced",
)
```

`C=50` was selected via a 3-round benchmark comparing detection rates against the deepset and Gandalf test sets. Higher values of C reduce regularization and improve recall on hard injection variants without increasing the false positive rate at this dataset scale.

## 6 Heuristic Features

These features catch semantic injection patterns that TF-IDF character n-grams miss. They are computed by `zugashield.ml.features.compute_heuristic_features`.

| # | Feature | What It Catches |
|---|---------|-----------------|
| 1 | Override keyword density | `ignore`, `disregard`, `bypass`, `pretend`, `act as`, etc. |
| 2 | Few-shot pattern count | Fake conversation turns (`Q:`, `A:`, `User:`, `Assistant:`, `System:`) |
| 3 | Special token density | `<system>`, `[INST]`, `\|endoftext\|`, template markers |
| 4 | Repeated token indicator | Any word appearing >3 times (padding attacks) |
| 5 | Imperative sentence density | Sentences starting with command verbs (`ignore`, `reveal`, `execute`, etc.) |
| 6 | Second-person pronoun ratio | `you will / must / are` patterns (directing the LLM) |

`NUM_HEURISTIC_FEATURES = 6` is exported from `zugashield.ml.features` and used at both training and inference to ensure parity.

## Training Data

9 public Hugging Face datasets (~20,000+ samples total):

| Dataset | Type | Size |
|---------|------|------|
| `deepset/prompt-injections` | Labeled injection + benign | ~546 |
| `Lakera/gandalf_ignore_instructions` | Injection (all positive) | ~777 |
| `rubend18/ChatGPT-Jailbreak-Prompts` | Jailbreak prompts | ~79 |
| `JailbreakBench/JBB-Behaviors` | Harmful behaviors (NeurIPS 2024) | ~100 |
| `jackhhao/jailbreak-classification` | Jailbreak + benign | ~1,044 |
| `reshabhs/SPML_Chatbot_Prompt_Injection` | GPT-4 semantic attacks | up to 5K (capped) |
| `Lakera/mosscap_prompt_injection` | DEF CON 31 red-team (levels 4-8) | up to 5K (capped) |
| `xTRam1/safe-guard-prompt-injection` | Categorical taxonomy | ~10K |
| `qualifire/prompt-injections-benchmark` | 2025 hard negatives | ~5K |

The SPML and Mosscap datasets are capped at 5,000 samples to prevent a single source from dominating the training distribution.

## Model Bundle Format

The saved `.joblib` file is a dict:

```python
{
    "tfidf": TfidfVectorizer,
    "clf": LogisticRegression,
    "has_heuristic_features": True,
    "n_heuristic_features": 6,
    "__zugashield_meta__": {
        "version": "2.0.0",
        "trained_at": "2026-02-17T00:00:00+00:00",
        "samples": 20000,
        "cv_f1": 0.912,
        "datasets": ["deepset", "gandalf", "rubend18", ...]
    }
}
```

## Default Location

The bundled model ships with the package:

```
zugashield/models/tfidf_injection.joblib
```

A user-retrained model can be placed at:

```
~/.zugashield/models/tfidf_injection.joblib
```

The user path takes precedence over the bundled model.

Last Updated: 2026-02-17
