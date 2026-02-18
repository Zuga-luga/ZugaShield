"""
ZugaShield ML — Heuristic Feature Computation
===============================================

Six fast-compute features that catch semantic injection patterns
TF-IDF char n-grams miss. Used by both ``train_tfidf.py`` (training)
and ``ml_detector.py`` (inference) to ensure feature parity.

Each feature targets a specific semantic attack class:
    1. Override keyword density   — "ignore", "disregard", "bypass", etc.
    2. Few-shot pattern count     — fake Q&A turns (User:/Assistant:/System:)
    3. Special token density      — <system>, [INST], |endoftext|, etc.
    4. Repeated token indicator   — word repeated >3 times (padding attacks)
    5. Imperative sentence density — sentences starting with commands
    6. Second-person pronoun ratio — "you will/must/are" (directing the LLM)
"""

from __future__ import annotations

import re
from collections import Counter
from typing import List

# Keywords that signal instruction override attempts
OVERRIDE_KEYWORDS = [
    "ignore", "disregard", "forget", "override", "bypass",
    "pretend", "roleplay", "hypothetically", "suppose",
    "your new task", "new instructions", "system prompt",
    "you are now", "act as", "from now on", "instead",
]

# Imperative verbs that commonly start injection sentences
IMPERATIVE_VERBS = frozenset({
    "ignore", "forget", "disregard", "reveal", "output", "print",
    "show", "tell", "give", "write", "generate", "create", "list",
    "execute", "run", "do", "pretend", "act", "become", "switch",
})

# Regex for fake conversation turn markers
_SHOT_PATTERN = re.compile(
    r'(Q:|A:|User:|Assistant:|Human:|Bot:|System:)', re.IGNORECASE,
)

# Regex for special/template tokens
_SPECIAL_PATTERN = re.compile(r'[<>{}\[\]|`]')

# Regex for second-person pronouns
_YOU_PATTERN = re.compile(r'\byou\b', re.IGNORECASE)

# Regex for sentence splitting
_SENTENCE_SPLIT = re.compile(r'[.!?\n]')


def compute_heuristic_features(text: str) -> List[float]:
    """
    Compute 6 heuristic features from input text.

    Returns a list of 6 floats suitable for concatenation with TF-IDF
    sparse features via ``scipy.sparse.hstack``.
    """
    text_lower = text.lower()
    tokens = text_lower.split()
    n_tokens = max(len(tokens), 1)
    n_chars = max(len(text), 1)

    # 1. Override keyword density
    kw_count = sum(1 for kw in OVERRIDE_KEYWORDS if kw in text_lower)
    kw_density = kw_count / n_tokens

    # 2. Few-shot pattern count (fake Q&A turns)
    shot_count = float(len(_SHOT_PATTERN.findall(text)))

    # 3. Special token density
    special_count = len(_SPECIAL_PATTERN.findall(text))
    special_density = special_count / n_chars

    # 4. Repeated token indicator (any word appears >3 times)
    token_counts = Counter(tokens)
    max_repeat = max(token_counts.values(), default=0)
    has_repeat = float(max_repeat > 3)

    # 5. Imperative sentence density
    sentences = [s.strip() for s in _SENTENCE_SPLIT.split(text) if s.strip()]
    if sentences:
        imp_count = sum(
            1 for s in sentences
            if s.split()[0].lower() in IMPERATIVE_VERBS
        )
        imp_density = imp_count / max(len(sentences), 1)
    else:
        imp_density = 0.0

    # 6. Second-person pronoun ratio ("you will/must/are")
    you_count = len(_YOU_PATTERN.findall(text))
    pronoun_ratio = you_count / n_tokens

    return [kw_density, shot_count, special_density, has_repeat, imp_density, pronoun_ratio]


# Number of features produced — used for validation in training/inference
NUM_HEURISTIC_FEATURES = 6
