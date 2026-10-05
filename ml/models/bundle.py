"""Versioned model bundle: everything inference needs, saved together."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
from scipy import sparse

from ml.config import MODELS_DIR
from ml.features.pipeline import EmailFeatures, FeatureBuilder


@dataclass
class ModelBundle:
    candidate: str
    features: FeatureBuilder
    classifier: object
    threshold: float
    dense: bool = False
    metadata: dict = field(default_factory=dict)

    def matrix(self, items: list[EmailFeatures]):
        x = self.features.transform(items)
        return x.toarray() if self.dense else x

    def predict_proba(self, items: list[EmailFeatures]) -> np.ndarray:
        return self.classifier.predict_proba(self.matrix(items))[:, 1]

    @property
    def is_linear(self) -> bool:
        return hasattr(self.classifier, "coef_")

    def contributions(self, item: EmailFeatures) -> tuple[np.ndarray, list[tuple[str, str]]]:
        """Exact per-feature contributions to the log-odds (linear models only)."""
        x = sparse.csr_matrix(self.features.transform([item]))
        coef = np.asarray(self.classifier.coef_).ravel()
        return x.multiply(coef).toarray().ravel(), self.features.feature_names()


def version_dir(version: str) -> Path:
    return MODELS_DIR / f"v{version}"


def save_bundle(bundle: ModelBundle, version: str, metrics: dict) -> Path:
    directory = version_dir(version)
    directory.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, directory / "model.joblib", compress=3)
    (directory / "metadata.json").write_text(json.dumps(bundle.metadata, indent=2))
    (directory / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (MODELS_DIR / "LATEST").write_text(version + "\n")
    return directory


def latest_version() -> str | None:
    marker = MODELS_DIR / "LATEST"
    return marker.read_text().strip() if marker.exists() else None


def load_bundle(version: str | None = None) -> ModelBundle:
    version = version or latest_version()
    if not version:
        raise FileNotFoundError("No trained model found - run `python3 -m ml.training.train`")
    return joblib.load(version_dir(version) / "model.joblib")
