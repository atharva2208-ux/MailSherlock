"""Model loading, prediction and per-message explanation."""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass

import numpy as np

from ml.features.pipeline import featurise_raw
from ml.features.structural import HUMAN_NAMES
from ml.models.bundle import ModelBundle, load_bundle, version_dir

TOP_TERMS = 8


def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


@dataclass
class Prediction:
    probability: float
    threshold: float
    label: str
    confidence: str
    margin: float
    vocabulary_coverage: float
    signals: list[dict]
    inference_ms: float

    def as_dict(self) -> dict:
        return self.__dict__.copy()


class Predictor:
    def __init__(self, bundle: ModelBundle):
        self.bundle = bundle
        directory = version_dir(bundle.metadata["model_version"])
        metrics_path = directory / "metrics.json"
        self.metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else {}
        self._word_vocab = (
            bundle.features.word_vectorizer.vocabulary_ if bundle.features.use_words else {}
        )

    @classmethod
    def load(cls, version: str | None = None) -> "Predictor":
        return cls(load_bundle(version))

    @property
    def metadata(self) -> dict:
        return self.bundle.metadata

    def _coverage(self, text: str) -> float:
        """Share of the message's words the model has a weight for.

        Low coverage means the model is extrapolating (other language, very
        short message, unusual domain) and its probability deserves less trust.
        """
        if not self._word_vocab:
            return 1.0
        tokens = [t for t in text.split() if t.isalpha() and len(t) > 1]
        if not tokens:
            return 0.0
        return sum(t in self._word_vocab for t in tokens) / len(tokens)

    def _signals(self, features) -> list[dict]:
        if not self.bundle.is_linear:
            return []
        contributions, names = self.bundle.contributions(features)
        signals: list[dict] = []
        char_total = 0.0
        word_items: list[tuple[float, str]] = []
        for index in np.flatnonzero(contributions):
            kind, name = names[index]
            value = float(contributions[index])
            if kind == "char":
                char_total += value
            elif kind == "word":
                word_items.append((value, name))
            else:
                signals.append({"kind": "structural", "feature": HUMAN_NAMES.get(name, name), "weight": round(value, 4)})

        word_items.sort(key=lambda item: item[0], reverse=True)
        positive = [w for w in word_items if w[0] > 0][:TOP_TERMS]
        negative = [w for w in reversed(word_items) if w[0] < 0][: TOP_TERMS // 2]
        for value, name in positive + negative:
            signals.append({"kind": "term", "feature": name, "weight": round(value, 4)})
        if char_total:
            signals.append({"kind": "character_patterns", "feature": "Character n-gram patterns", "weight": round(char_total, 4)})
        return sorted(signals, key=lambda s: abs(s["weight"]), reverse=True)

    def predict_raw(self, raw: bytes) -> Prediction:
        started = time.perf_counter()
        features, _ = featurise_raw(raw)
        probability = float(self.bundle.predict_proba([features])[0])
        threshold = float(self.bundle.threshold)
        margin = _logit(probability) - _logit(threshold)
        coverage = self._coverage(features.text)
        confidence = "high" if abs(margin) >= 3 else "medium" if abs(margin) >= 1.2 else "low"
        if coverage < 0.5 or len(features.text) < 80:
            confidence = "low"
        return Prediction(
            probability=round(probability, 4),
            threshold=round(threshold, 4),
            label="phishing" if probability >= threshold else "legitimate",
            confidence=confidence,
            margin=round(margin, 3),
            vocabulary_coverage=round(coverage, 3),
            signals=self._signals(features),
            inference_ms=round((time.perf_counter() - started) * 1000, 2),
        )
