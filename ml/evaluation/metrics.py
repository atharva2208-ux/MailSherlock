"""Metric computation. Every figure MailSherlock reports comes from here."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve


def threshold_for_max_fpr(y_true: np.ndarray, scores: np.ndarray, max_fpr: float) -> float:
    """Lowest threshold whose false-positive rate stays within ``max_fpr``.

    The lowest admissible threshold maximises recall under the FPR budget.
    """
    fpr, _, thresholds = roc_curve(y_true, scores)
    admissible = thresholds[(fpr <= max_fpr) & np.isfinite(thresholds)]
    if admissible.size == 0:
        return 1.0
    return float(min(admissible.min() + 1e-9, 1.0))


def classification_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict:
    y_true = np.asarray(y_true).astype(int)
    predicted = (scores >= threshold).astype(int)
    tp = int(((predicted == 1) & (y_true == 1)).sum())
    tn = int(((predicted == 0) & (y_true == 0)).sum())
    fp = int(((predicted == 1) & (y_true == 0)).sum())
    fn = int(((predicted == 0) & (y_true == 1)).sum())

    def safe(n: float, d: float) -> float | None:
        return round(n / d, 4) if d else None

    precision = safe(tp, tp + fp)
    recall = safe(tp, tp + fn)
    both_classes = len(np.unique(y_true)) == 2
    return {
        "samples": int(len(y_true)),
        "phishing": int(y_true.sum()),
        "legitimate": int((1 - y_true).sum()),
        "threshold": round(float(threshold), 4),
        "precision": precision,
        "recall": recall,
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision and recall else None,
        "accuracy": safe(tp + tn, len(y_true)),
        "false_positive_rate": safe(fp, fp + tn),
        "false_negative_rate": safe(fn, fn + tp),
        "roc_auc": round(float(roc_auc_score(y_true, scores)), 4) if both_classes else None,
        "pr_auc": round(float(average_precision_score(y_true, scores)), 4) if both_classes else None,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def recall_at_fpr(y_true: np.ndarray, scores: np.ndarray, max_fpr: float) -> float:
    fpr, tpr, _ = roc_curve(y_true, scores)
    feasible = tpr[fpr <= max_fpr]
    return float(feasible.max()) if feasible.size else 0.0
