import pytest

from ml.models.bundle import latest_version

pytestmark = pytest.mark.skipif(latest_version() is None, reason="no trained model artifact")


@pytest.fixture(scope="module")
def predictor():
    from ml.inference.predictor import Predictor

    return Predictor.load()


def test_prediction_is_deterministic_and_bounded(predictor, sample_bytes):
    raw = sample_bytes("phishing/paypal-alert.eml")
    first, second = predictor.predict_raw(raw), predictor.predict_raw(raw)
    assert 0.0 <= first.probability <= 1.0
    assert first.probability == second.probability
    assert first.label == ("phishing" if first.probability >= first.threshold else "legitimate")


def test_explanations_are_exact_linear_contributions(predictor, sample_bytes):
    import numpy as np

    from ml.features.pipeline import featurise_raw

    features, _ = featurise_raw(sample_bytes("phishing/microsoft-account.eml"))
    contributions, _ = predictor.bundle.contributions(features)
    intercept = float(np.ravel(predictor.bundle.classifier.intercept_)[0])
    logit = contributions.sum() + intercept
    probability = 1 / (1 + np.exp(-logit))
    assert probability == pytest.approx(predictor.bundle.predict_proba([features])[0], abs=1e-6)


def test_signals_are_sorted_and_labelled(predictor, sample_bytes):
    prediction = predictor.predict_raw(sample_bytes("phishing/microsoft-account.eml"))
    weights = [abs(s["weight"]) for s in prediction.signals]
    assert weights == sorted(weights, reverse=True)
    assert {s["kind"] for s in prediction.signals} <= {"term", "structural", "character_patterns"}


def test_metadata_records_versions_and_threshold(predictor):
    meta = predictor.metadata
    for key in ("model_version", "dataset_version", "feature_version", "training_date", "training_samples", "threshold"):
        assert key in meta
    assert predictor.metrics["test"]["confusion_matrix"]


def test_short_or_foreign_text_lowers_confidence(predictor):
    raw = "Subject: hola\nContent-Type: text/plain\n\nhola qué tal\n".encode()
    assert predictor.predict_raw(raw).confidence == "low"
