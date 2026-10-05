"""Stage 3: evaluate a trained bundle on the held-out test split and the challenge set.

Usage::

    python3 -m ml.evaluation.evaluate          # re-evaluates the latest model
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from ml.datasets.loader import load_challenge, load_split
from ml.evaluation.metrics import classification_metrics
from ml.features.structural import HUMAN_NAMES
from ml.models.bundle import ModelBundle, load_bundle, version_dir

TOP_FEATURES = 25


def global_feature_weights(bundle: ModelBundle) -> dict | None:
    """Largest positive/negative coefficients - used to audit for leakage.

    If corpus artefacts (dataset-specific tokens, dates, list names) appear
    here, the model is learning the dataset rather than the task.
    """
    if not bundle.is_linear:
        return None
    coef = np.asarray(bundle.classifier.coef_).ravel()
    names = bundle.features.feature_names()
    order = np.argsort(coef)

    def describe(index: int) -> dict:
        kind, name = names[index]
        return {"kind": kind, "feature": HUMAN_NAMES.get(name, name), "weight": round(float(coef[index]), 4)}

    return {
        "phishing": [describe(i) for i in order[::-1][:TOP_FEATURES]],
        "legitimate": [describe(i) for i in order[:TOP_FEATURES]],
    }


def evaluate_bundle(bundle: ModelBundle) -> dict:
    test_x, test_y, test_meta = load_split("test")
    test_scores = bundle.predict_proba(test_x)
    test_metrics = classification_metrics(test_y, test_scores, bundle.threshold)
    test_metrics["at_threshold_0_5"] = classification_metrics(test_y, test_scores, 0.5)

    errors = []
    for meta, label, score in zip(test_meta, test_y, test_scores):
        predicted = int(score >= bundle.threshold)
        if predicted != label:
            errors.append(
                {"id": meta["id"], "label": "phishing" if label else "legitimate", "score": round(float(score), 4)}
            )
    errors.sort(key=lambda e: abs(e["score"] - bundle.threshold), reverse=True)

    challenge_x, challenge_y, challenge_meta = load_challenge()
    challenge_scores = bundle.predict_proba(challenge_x)
    challenge = classification_metrics(challenge_y, challenge_scores, bundle.threshold)
    challenge["predictions"] = [
        {
            "id": m["id"],
            "subject": m["subject"],
            "label": m["label"],
            "probability": round(float(s), 4),
            "predicted": "phishing" if s >= bundle.threshold else "legitimate",
        }
        for m, s in zip(challenge_meta, challenge_scores)
    ]

    return {
        "model_version": bundle.metadata.get("model_version"),
        "threshold": round(bundle.threshold, 6),
        "test": test_metrics,
        "test_errors": errors[:40],
        "challenge": challenge,
        "feature_weights": global_feature_weights(bundle),
    }


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def _eligibility(row: dict) -> str:
    if row.get("prior_violations"):
        names = ", ".join(v["feature"] for v in row["prior_violations"])
        return f"no - contradicts priors ({names})"
    return "yes" if row.get("eligible", row["explainable"]) else "no - not decomposable"


def write_report(bundle: ModelBundle, metrics: dict, directory: Path) -> None:
    meta = bundle.metadata
    test, challenge, val = metrics["test"], metrics["challenge"], metrics.get("validation", {})
    lines = [
        f"# {meta['model_name']} v{meta['model_version']} - evaluation report",
        "",
        f"- Trained: {meta['training_date']}",
        f"- Selected candidate: `{meta['candidate']}` - {meta['description']}",
        f"- Dataset version: {meta['dataset_version']}; feature version: {meta['feature_version']}",
        f"- Decision threshold: **{meta['threshold']:.4f}** ({meta['threshold_policy']})",
        "",
        "## Candidate comparison (validation split)",
        "",
        "| Candidate | Eligible | Recall @ FPR<=1% | PR-AUC | ROC-AUC | Train (s) |",
        "|---|---|---|---|---|---|",
    ]
    for row in meta["selection"]["candidates"]:
        lines.append(
            f"| {row['candidate']} | {_eligibility(row)} | {_pct(row['recall_at_target_fpr'])} "
            f"| {row['validation']['pr_auc']} | {row['validation']['roc_auc']} | {row['train_seconds']} |"
        )
    lines += ["", "## Held-out test split", ""]
    lines += ["| Metric | Tuned threshold | Threshold 0.5 |", "|---|---|---|"]
    at05 = test["at_threshold_0_5"]
    for key in ("precision", "recall", "f1", "accuracy", "false_positive_rate", "false_negative_rate"):
        lines.append(f"| {key.replace('_', ' ')} | {_pct(test[key])} | {_pct(at05[key])} |")
    lines.append(f"| ROC-AUC | {test['roc_auc']} | |")
    lines.append(f"| PR-AUC | {test['pr_auc']} | |")
    cm = test["confusion_matrix"]
    lines += [
        "",
        f"Confusion matrix (n={test['samples']}): TP {cm['tp']} | FP {cm['fp']} | TN {cm['tn']} | FN {cm['fn']}",
        "",
        "## Modern challenge set (evaluation only)",
        "",
        f"{challenge['legitimate']} legitimate and {challenge['phishing']} phishing hand-written modern emails. "
        f"False positives: **{challenge['confusion_matrix']['fp']} / {challenge['legitimate']}**; "
        f"missed phishing: **{challenge['confusion_matrix']['fn']} / {challenge['phishing']}**.",
        "",
        "| Subject | Label | P(phishing) | Predicted |",
        "|---|---|---|---|",
    ]
    for p in challenge["predictions"]:
        flag = "" if p["predicted"] == p["label"] else " **(error)**"
        lines.append(f"| {p['subject']} | {p['label']} | {p['probability']:.3f} | {p['predicted']}{flag} |")
    if val:
        lines += ["", f"Validation (threshold selection split): recall {_pct(val['recall'])}, "
                  f"FPR {_pct(val['false_positive_rate'])}, precision {_pct(val['precision'])}."]
    if metrics.get("feature_weights"):
        lines += ["", "## Strongest global weights (leakage audit)", "", "| Toward phishing | Toward legitimate |", "|---|---|"]
        for a, b in zip(metrics["feature_weights"]["phishing"][:15], metrics["feature_weights"]["legitimate"][:15]):
            lines.append(f"| {a['kind']}: `{a['feature']}` ({a['weight']}) | {b['kind']}: `{b['feature']}` ({b['weight']}) |")
    (directory / "report.md").write_text("\n".join(lines) + "\n")


def main() -> int:
    bundle = load_bundle()
    directory = version_dir(bundle.metadata["model_version"])
    previous = json.loads((directory / "metrics.json").read_text()) if (directory / "metrics.json").exists() else {}
    metrics = evaluate_bundle(bundle)
    if "validation" in previous:
        metrics["validation"] = previous["validation"]
    (directory / "metrics.json").write_text(json.dumps(metrics, indent=2))
    write_report(bundle, metrics, directory)
    print(json.dumps({k: metrics[k] for k in ("test", "challenge")}, indent=2, default=str)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
