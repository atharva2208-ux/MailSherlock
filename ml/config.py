"""Central configuration for the MailSherlock ML pipeline.

Every stage reads paths and versions from here so a training run is fully
described by this file plus the dataset manifest.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SPLIT_DIRS = {
    "train": DATA_DIR / "train",
    "validation": DATA_DIR / "validation",
    "test": DATA_DIR / "test",
}
ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
MODELS_DIR = ARTIFACTS_DIR / "models"
CHALLENGE_SET = Path(__file__).resolve().parent / "datasets" / "challenge" / "challenge.jsonl"

MODEL_NAME = "MailSherlock Phishing Classifier"
MODEL_VERSION = "1.0.0"
DATASET_VERSION = "2026.10-pp-sa"
FEATURE_VERSION = "f1"

RANDOM_SEED = 1337

# Split proportions are applied to near-duplicate *groups*, not messages,
# so a campaign never straddles train and test.
SPLIT_FRACTIONS = {"train": 0.70, "validation": 0.15, "test": 0.15}

# Two messages whose normalised text has cosine similarity above this value
# are treated as the same template/campaign for splitting purposes.
NEAR_DUPLICATE_SIMILARITY = 0.80

# Threshold selection: maximise recall subject to this false-positive budget
# on the validation split.
TARGET_MAX_FPR = 0.01

MAX_BODY_CHARS = 6000
MAX_EMAIL_BYTES = 2_000_000

LABELS = {"legitimate": 0, "phishing": 1}
