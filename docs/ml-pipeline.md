# ML pipeline

```
npm run ml:fetch        scripts/fetch-datasets.sh
npm run ml:preprocess   ml/preprocessing/preprocess.py   load → validate → normalise → dedup → group → split
npm run ml:train        ml/training/train.py             candidates → selection → threshold → evaluate → save
npm run ml:evaluate     ml/evaluation/evaluate.py        re-evaluate the latest model
npm run ml:predict      ml/inference/predict.py          CLI scoring of .eml files
npm run ml:serve        ml/inference/service.py          HTTP service used by the API
npm run ml:test         pytest ml/tests
```

All randomness uses `RANDOM_SEED = 1337` (`ml/config.py`).

## Representation

`ml/preprocessing/email_text.py` parses the raw message with Python's `email` package and extracts the visible body (plain part, or text rendered from HTML), anchors, forms, hidden elements and attachment names. `normalise_text` then:

- strips subject prefixes and list tags, and scrubs corpus artefacts
- masks URLs (`urltoken`), email addresses (`emailtoken`) and numbers (`0`)
- lowercases and truncates to 6,000 characters

## Features

| Block            | Details                                                                                                                                                                                                                                                                                                                                                                     |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Word TF-IDF      | 1-2 grams, `min_df=3`, `max_df=0.9`, 40k features, sublinear TF                                                                                                                                                                                                                                                                                                             |
| Character TF-IDF | `char_wb` 3-5 grams, `min_df=5`, 40k features, sublinear TF; robust to obfuscated spellings                                                                                                                                                                                                                                                                                 |
| Structural (25)  | URL count, distinct domains, IP/`@`/shortener/punycode URLs, high-abuse TLD ratio, URL length, subdomain depth, credential-path ratio, encoding, anchor/href mismatch, hostname entropy, forms, password inputs, hidden elements, scripts, attachments, dangerous and double extensions, body length, uppercase ratio, exclamation rate, urgency and credential term counts |

`min_df` also keeps one-off tokens such as names and order numbers out of the vocabulary.

## Candidates and selection

`ml/models/candidates.py` defines six candidates:

- word-only logistic regression
- word + character logistic regression
- word + character + structural logistic regression
- calibrated linear SVM
- complement naive Bayes
- gradient boosting on structural features

Each is fitted on train and scored on validation.

A candidate is **eligible** for production only if:

1. It is linear, so `xᵢ · wᵢ` gives an exact per-message explanation.
2. No structural feature with an unambiguous security direction (forms, password fields, IP URLs, double extensions, subdomain depth and others) has a coefficient below −0.25.

The selected model is the eligible candidate with the highest validation recall at FPR ≤ 1%, with PR-AUC as tie-breaker. Opaque candidates are still trained, so the cost of the explainability requirement is measured rather than assumed. In the current run it costs 0.2 points of recall.

## Threshold

The threshold is the lowest validation threshold with FPR ≤ 1% (`TARGET_MAX_FPR`), which maximises recall within the false-positive budget. The current model uses **0.5544**.

On the test split this gives 0.34% FPR and 95.98% recall, against 0.51% FPR and 97.10% recall at 0.5. The tuned threshold trades about one percentage point of recall for roughly a third fewer false positives on legitimate mail, which is the error users notice and lose trust over. The hybrid engine recovers recall through rule evidence.

## Evaluation outputs

`ml/artifacts/models/v<version>/` contains:

- `model.joblib`: feature builder, classifier and threshold
- `metadata.json`: versions, training date, sample counts, threshold policy, data sources, environment and the full candidate table
- `metrics.json`: test metrics at the tuned threshold and at 0.5, misclassified test ids, challenge-set predictions, global weights
- `report.md`: human-readable summary

`ml/artifacts/models/LATEST` names the version the service loads.

## Explanations

`ModelBundle.contributions` multiplies the sparse feature vector by the coefficient vector. The predictor reports:

- the strongest word terms toward each class
- structural features
- the summed character n-gram contribution

`ml/tests/test_inference.py` asserts that contributions plus intercept reproduce the predicted probability. Confidence is derived from the logit distance to the threshold, and is forced to "low" for short messages or vocabulary coverage below 50%.

## Feedback

Analyst feedback is stored in the `feedback` table with `reviewed = 0`. Retraining should export only reviewed rows, add them as a separate dataset source with their own group ids, and go through the same split and selection process. The production model is never updated automatically.
