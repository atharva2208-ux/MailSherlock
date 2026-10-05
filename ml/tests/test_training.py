import numpy as np
import pytest

from ml.evaluation.metrics import classification_metrics, threshold_for_max_fpr
from ml.features.pipeline import FeatureBuilder, featurise_raw
from ml.models.candidates import prior_violations
from sklearn.linear_model import LogisticRegression


def test_threshold_respects_fpr_budget():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(500), np.ones(500)]
    scores = np.r_[rng.beta(2, 5, 500), rng.beta(5, 2, 500)]
    threshold = threshold_for_max_fpr(y, scores, 0.01)
    metrics = classification_metrics(y, scores, threshold)
    assert metrics["false_positive_rate"] <= 0.01
    loose = classification_metrics(y, scores, 0.5)
    assert metrics["recall"] <= loose["recall"]


def test_classification_metrics_confusion_matrix():
    metrics = classification_metrics(np.array([1, 1, 0, 0]), np.array([0.9, 0.2, 0.8, 0.1]), 0.5)
    assert metrics["confusion_matrix"] == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}
    assert metrics["precision"] == 0.5 and metrics["false_positive_rate"] == 0.5


def test_prior_violation_gate_flags_counter_intuitive_weights(sample_bytes):
    items = [featurise_raw(sample_bytes(n))[0] for n in ("phishing/credential-harvest.eml", "legitimate/normal-newsletter.eml")] * 5
    builder = FeatureBuilder(use_words=False, use_chars=False, use_structural=True)
    x = builder.fit_transform(items)
    model = LogisticRegression().fit(x, [1, 0] * 5)
    model.coef_[0, :] = 0.0
    model.coef_[0, [n for _, n in builder.feature_names()].index("form_present")] = -2.0
    assert [v["feature"] for v in prior_violations(builder, model)] == ["form_present"]
    model.coef_[0, :] = 0.5
    assert prior_violations(builder, model) == []
