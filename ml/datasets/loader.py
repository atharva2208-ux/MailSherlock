"""Load processed splits and the challenge set as model inputs."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from ml.config import CHALLENGE_SET, LABELS, SPLIT_DIRS
from ml.features.pipeline import EmailFeatures, featurise_raw


def load_split(name: str) -> tuple[list[EmailFeatures], np.ndarray, list[dict]]:
    path: Path = SPLIT_DIRS[name] / "emails.jsonl"
    if not path.exists():
        raise FileNotFoundError(f"{path} missing - run `python3 -m ml.preprocessing.preprocess`")
    items, labels, meta = [], [], []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            items.append(EmailFeatures(record["text"], np.asarray(record["structural"], dtype=np.float64)))
            labels.append(LABELS[record["label"]])
            meta.append({"id": record["id"], "group": record["group"], "source": record["source"]})
    return items, np.asarray(labels), meta


def challenge_raw_messages() -> list[tuple[dict, bytes]]:
    """Challenge records rendered as minimal RFC 5322 messages, so they go
    through exactly the same parser as production traffic."""
    out = []
    with CHALLENGE_SET.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            raw = (
                f"From: sender@example.com\nTo: analyst@example.org\nSubject: {record['subject']}\n"
                f"MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n{record['body']}\n"
            ).encode("utf-8")
            out.append((record, raw))
    return out


def load_challenge() -> tuple[list[EmailFeatures], np.ndarray, list[dict]]:
    items, labels, meta = [], [], []
    for record, raw in challenge_raw_messages():
        features, _ = featurise_raw(raw)
        items.append(features)
        labels.append(LABELS[record["label"]])
        meta.append({"id": record["id"], "subject": record["subject"], "label": record["label"]})
    return items, np.asarray(labels), meta
