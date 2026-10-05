"""Stage 2: train candidates, select one on validation, tune its threshold, save it.

Usage::

    python3 -m ml.training.train
"""

from __future__ import annotations

import json
import platform
import time
from datetime import datetime, timezone

import numpy as np
import sklearn

from ml.config import (
    DATASET_VERSION,
    FEATURE_VERSION,
    MODEL_NAME,
    MODEL_VERSION,
    PROCESSED_DIR,
    RANDOM_SEED,
    TARGET_MAX_FPR,
)
from ml.datasets.loader import load_split
from ml.evaluation.evaluate import evaluate_bundle, write_report
from ml.evaluation.metrics import classification_metrics, recall_at_fpr, threshold_for_max_fpr
from ml.models.bundle import ModelBundle, save_bundle
from ml.models.candidates import CANDIDATES, prior_violations

# Production models must be eligible: their decision decomposes exactly into
# per-feature contributions (shown to analysts) and their structural weights
# agree with security priors. Opaque candidates are trained as benchmarks so
# the cost of that requirement is measured, not assumed.


def main() -> int:
    np.random.seed(RANDOM_SEED)
    train_x, train_y, _ = load_split("train")
    val_x, val_y, _ = load_split("validation")
    print(f"train={len(train_y)} (phishing {train_y.sum()})  validation={len(val_y)} (phishing {val_y.sum()})")

    results = []
    fitted: dict[str, ModelBundle] = {}
    for candidate in CANDIDATES:
        started = time.perf_counter()
        features = candidate.make_features()
        x_train = features.fit_transform(train_x)
        classifier = candidate.make_classifier()
        classifier.fit(x_train.toarray() if candidate.dense else x_train, train_y)
        bundle = ModelBundle(candidate.key, features, classifier, threshold=0.5, dense=candidate.dense)
        scores = bundle.predict_proba(val_x)
        threshold = threshold_for_max_fpr(val_y, scores, TARGET_MAX_FPR)
        bundle.threshold = threshold
        metrics = classification_metrics(val_y, scores, threshold)
        violations = prior_violations(features, classifier)
        row = {
            "candidate": candidate.key,
            "description": candidate.description,
            "explainable": candidate.explainable,
            "prior_violations": violations,
            "eligible": candidate.explainable and not violations,
            "recall_at_target_fpr": round(recall_at_fpr(val_y, scores, TARGET_MAX_FPR), 4),
            "validation": metrics,
            "validation_at_0_5": classification_metrics(val_y, scores, 0.5),
            "train_seconds": round(time.perf_counter() - started, 2),
        }
        results.append(row)
        fitted[candidate.key] = bundle
        print(
            f"  {candidate.key:16s} recall@FPR<={TARGET_MAX_FPR:.0%}={row['recall_at_target_fpr']:.4f} "
            f"pr_auc={metrics['pr_auc']} roc_auc={metrics['roc_auc']} ({row['train_seconds']}s)"
            + (f"  REJECTED prior violations: {violations}" if violations else "")
        )

    ranked = sorted(results, key=lambda r: (r["recall_at_target_fpr"], r["validation"]["pr_auc"]), reverse=True)
    chosen = next(r for r in ranked if r["eligible"])
    bundle = fitted[chosen["candidate"]]
    print(f"selected: {chosen['candidate']} (threshold {bundle.threshold:.4f})")

    manifest = json.loads((PROCESSED_DIR / "manifest.json").read_text())
    bundle.metadata = {
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "dataset_version": DATASET_VERSION,
        "feature_version": FEATURE_VERSION,
        "candidate": chosen["candidate"],
        "description": chosen["description"],
        "training_date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "training_samples": int(len(train_y)),
        "training_phishing": int(train_y.sum()),
        "training_legitimate": int(len(train_y) - train_y.sum()),
        "validation_samples": int(len(val_y)),
        "threshold": round(bundle.threshold, 6),
        "threshold_policy": f"lowest validation threshold with false-positive rate <= {TARGET_MAX_FPR:.0%}",
        "seed": RANDOM_SEED,
        "dataset_sources": manifest["sources"],
        "environment": {"python": platform.python_version(), "scikit_learn": sklearn.__version__},
        "selection": {
            "criterion": f"highest validation recall at FPR <= {TARGET_MAX_FPR:.0%} (then PR-AUC) among "
            "eligible candidates: linear, exactly decomposable, and no structural weight contradicting "
            "security priors",
            "candidates": results,
        },
    }

    metrics = evaluate_bundle(bundle)
    metrics["validation"] = chosen["validation"]
    directory = save_bundle(bundle, MODEL_VERSION, metrics)
    write_report(bundle, metrics, directory)
    print(json.dumps({k: metrics[k] for k in ("test", "challenge")}, indent=2))
    print(f"saved -> {directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
