# ONNX DeBERTa Layer

ZugaShield supports an optional ONNX-based DeBERTa classifier as the second tier of ML detection. This layer runs after the TF-IDF classifier and handles semantic attacks that evade pattern-based detection.

## Install

```bash
pip install "zugashield[ml]"
# Pulls in: onnxruntime, tokenizers, optimum[onnxruntime], huggingface_hub
```

## Download CLI

The `zugashield-ml` CLI downloads, exports, and optionally quantizes ONNX models.

```bash
# Download default model (ProtectAI DeBERTa-base)
zugashield-ml download

# Download Meta Prompt Guard 2 (22M params, ~80-200ms CPU, gated)
zugashield-ml download --model prompt-guard-22m

# Download ProtectAI DeBERTa-small v2 (~100MB, pre-built ONNX)
zugashield-ml download --model deberta-small

# Skip INT8 quantization (keep full precision)
zugashield-ml download --no-quantize

# Custom model directory
zugashield-ml download --model-dir /opt/zugashield/models

# Show installed models and integrity status
zugashield-ml info

# Run latency benchmark (100 iterations)
zugashield-ml benchmark -n 100
```

## Model Registry

| Model Key | Hugging Face Repo | Description |
|-----------|-------------------|-------------|
| `deberta-base` | `protectai/deberta-v3-base-prompt-injection` | Default. 233MB quantized, ~1s CPU |
| `prompt-guard-22m` | `meta-llama/Llama-Prompt-Guard-2-22M` | Best accuracy/speed. 22M params, ~80-200ms CPU. Requires HF login (gated) |
| `deberta-small` | `protectai/deberta-v3-small-prompt-injection-v2` | ~100MB, pre-built ONNX available |

Default: `deberta-base`.

### Gated Models

`prompt-guard-22m` requires accepting the model license on Hugging Face and authenticating:

```bash
# 1. Accept license at: https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M
# 2. Log in:
huggingface-cli login
# 3. Download:
zugashield-ml download --model prompt-guard-22m
```

## Download Process

1. Export the HuggingFace model to ONNX format via `optimum.onnxruntime.ORTModelForSequenceClassification`
2. Download `tokenizer.json`
3. Apply INT8 dynamic quantization via `onnxruntime.quantization.quantize_dynamic` (unless `--no-quantize`)
4. Save as `deberta_injection.onnx` + `tokenizer.json` in the model directory
5. Write a SHA-256 sidecar file: `deberta_injection.onnx.sha256`

All models are saved under the same filename (`deberta_injection.onnx`) so the inference path in `MLDetectorLayer` is model-agnostic.

## Model Directory

Default: `~/.zugashield/models/`

Override via:
- CLI: `--model-dir /path/to/dir`
- Config: `ShieldConfig(ml_model_dir="/path/to/dir")`
- Environment: `ZUGASHIELD_ML_MODEL_DIR=/path/to/dir`

## Configuration

```python
from zugashield import ZugaShield
from zugashield.config import ShieldConfig

shield = ZugaShield(ShieldConfig(
    ml_detector_enabled=True,
    ml_onnx_enabled=True,               # Enable ONNX tier
    ml_confidence_threshold=0.7,        # Detection threshold (0.0-1.0)
    ml_model_dir="~/.zugashield/models",
    ml_model_version="",                # "" = accept any version
))
```

Or via builder:

```python
shield = (ZugaShield.builder()
    .enable_ml(model_dir="~/.zugashield/models", threshold=0.7)
    .build())
```

## Info Command

```bash
zugashield-ml info
```

Output:

```
ZugaShield ML — Model Info (~/.zugashield/models)

  TF-IDF (bundled): /path/to/zugashield/models/tfidf_injection.joblib (4.2 MB)
    Version:  2.0.0
    Trained:  2026-02-17T00:00:00+00:00
    Samples:  20000
    CV F1:    0.912
    Datasets: deepset, gandalf, rubend18, ...
    SHA-256:  abc123...

  ONNX DeBERTa:     ~/.zugashield/models/deberta_injection.onnx (58 MB)
  Tokenizer:        ~/.zugashield/models/tokenizer.json
    SHA-256:  def456...
    Integrity: VERIFIED

  Available models for download:
    deberta-base: ProtectAI DeBERTa-base (233MB quantized, ~1s CPU)
    prompt-guard-22m: Meta Prompt Guard 2 (22M params, ~80-200ms CPU, best accuracy/speed) (gated, requires login)
    deberta-small: ProtectAI DeBERTa-small v2 (~100MB, pre-built ONNX available)
```

## Knowledge Distillation

`zugashield.ml.distill` is a development script that uses the ONNX model as a teacher to pseudo-label unlabeled data for TF-IDF retraining.

```bash
python -m zugashield.ml.distill --confidence 0.95 --max-samples 10000
```

This produces a `pseudo_labels.jsonl` file that can be incorporated into future training runs.

Last Updated: 2026-02-17
