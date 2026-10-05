"""Candidate model definitions compared during training.

The linear models are preferred for production because their per-message
decisions decompose exactly into per-feature contributions, which is what the
ML assessment panel shows analysts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC

from ml.config import RANDOM_SEED
from ml.features.pipeline import FeatureBuilder


@dataclass(frozen=True)
class Candidate:
    key: str
    description: str
    explainable: bool
    make_features: Callable[[], FeatureBuilder]
    make_classifier: Callable[[], object]
    dense: bool = False


CANDIDATES: tuple[Candidate, ...] = (
    Candidate(
        "lr_words",
        "TF-IDF word 1-2 grams + logistic regression",
        True,
        lambda: FeatureBuilder(use_words=True, use_chars=False, use_structural=False),
        lambda: LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000, random_state=RANDOM_SEED),
    ),
    Candidate(
        "lr_text",
        "TF-IDF words + character 3-5 grams + logistic regression",
        True,
        lambda: FeatureBuilder(use_words=True, use_chars=True, use_structural=False),
        lambda: LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000, random_state=RANDOM_SEED),
    ),
    Candidate(
        "lr_hybrid",
        "TF-IDF words + character 3-5 grams + structural features + logistic regression",
        True,
        lambda: FeatureBuilder(),
        lambda: LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000, random_state=RANDOM_SEED),
    ),
    Candidate(
        "svm_hybrid",
        "Same features + linear SVM with sigmoid calibration",
        False,
        lambda: FeatureBuilder(),
        lambda: CalibratedClassifierCV(
            LinearSVC(C=0.5, class_weight="balanced", random_state=RANDOM_SEED), method="sigmoid", cv=3
        ),
    ),
    Candidate(
        "nb_words",
        "TF-IDF word 1-2 grams + complement naive Bayes",
        False,
        lambda: FeatureBuilder(use_words=True, use_chars=False, use_structural=False),
        lambda: ComplementNB(alpha=0.3),
    ),
    Candidate(
        "gbm_structural",
        "Structural features only + histogram gradient boosting",
        False,
        lambda: FeatureBuilder(use_words=False, use_chars=False, use_structural=True),
        lambda: HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, random_state=RANDOM_SEED),
        dense=True,
    ),
)


# Structural features whose effect on phishing likelihood is not in doubt.
# A model that learns a clearly *negative* weight for one of these has
# fitted a dataset artefact (e.g. 2002 marketing ham containing forms), and
# would show analysts explanations like "HTML form => legitimate".
NON_NEGATIVE_PRIORS = frozenset(
    {
        "ip_url",
        "at_symbol_url",
        "shortener_url",
        "suspicious_tld_ratio",
        "punycode_domain",
        "credential_path_ratio",
        "anchor_domain_mismatch",
        "form_present",
        "password_input",
        "hidden_elements",
        "script_present",
        "dangerous_attachment",
        "double_extension_attachment",
        "urgency_terms",
        "credential_terms",
        "max_subdomain_depth",
    }
)
PRIOR_VIOLATION_TOLERANCE = -0.25


def prior_violations(features: FeatureBuilder, classifier: object) -> list[dict]:
    """Structural coefficients that contradict security priors (empty if none or N/A)."""
    if not features.use_structural or not hasattr(classifier, "coef_"):
        return []
    coef = classifier.coef_.ravel()
    violations = []
    for (kind, name), weight in zip(features.feature_names(), coef):
        if kind == "structural" and name in NON_NEGATIVE_PRIORS and weight < PRIOR_VIOLATION_TOLERANCE:
            violations.append({"feature": name, "weight": round(float(weight), 4)})
    return violations
