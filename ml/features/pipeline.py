"""Feature construction shared by training and inference."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

from ml.features.structural import FEATURE_NAMES, extract_structural
from ml.preprocessing.email_text import ParsedEmail, normalise_text, parse_email


@dataclass
class EmailFeatures:
    text: str
    structural: np.ndarray


def featurise_raw(raw: bytes) -> tuple[EmailFeatures, ParsedEmail]:
    parsed = parse_email(raw)
    return EmailFeatures(normalise_text(parsed.subject, parsed.body), extract_structural(parsed)), parsed


class FeatureBuilder:
    """Word n-grams + character n-grams + scaled structural features.

    ``min_df`` keeps one-off tokens (names, order numbers, unique IDs) out of
    the vocabulary, which both regularises the model and avoids memorising
    personal details from the training mail.
    """

    def __init__(self, use_words: bool = True, use_chars: bool = True, use_structural: bool = True):
        self.use_words = use_words
        self.use_chars = use_chars
        self.use_structural = use_structural
        self.word_vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            min_df=3,
            max_df=0.9,
            max_features=40000,
            sublinear_tf=True,
            token_pattern=r"(?u)\b[a-z][a-z0-9']+\b",
            dtype=np.float32,
        )
        self.char_vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=5,
            max_features=40000,
            sublinear_tf=True,
            dtype=np.float32,
        )
        self.scaler = StandardScaler()

    def _blocks(self, items: Sequence[EmailFeatures], fit: bool) -> list[sparse.spmatrix]:
        texts = [i.text for i in items]
        blocks: list[sparse.spmatrix] = []
        if self.use_words:
            vec = self.word_vectorizer
            blocks.append(vec.fit_transform(texts) if fit else vec.transform(texts))
        if self.use_chars:
            vec = self.char_vectorizer
            blocks.append(vec.fit_transform(texts) if fit else vec.transform(texts))
        if self.use_structural:
            matrix = np.vstack([i.structural for i in items])
            scaled = self.scaler.fit_transform(matrix) if fit else self.scaler.transform(matrix)
            blocks.append(sparse.csr_matrix(np.clip(scaled, -5, 5)))
        return blocks

    def fit_transform(self, items: Sequence[EmailFeatures]) -> sparse.csr_matrix:
        return sparse.hstack(self._blocks(items, fit=True), format="csr")

    def transform(self, items: Sequence[EmailFeatures]) -> sparse.csr_matrix:
        return sparse.hstack(self._blocks(items, fit=False), format="csr")

    def feature_names(self) -> list[tuple[str, str]]:
        """(kind, name) for every column, in matrix order."""
        names: list[tuple[str, str]] = []
        if self.use_words:
            names += [("word", n) for n in self.word_vectorizer.get_feature_names_out()]
        if self.use_chars:
            names += [("char", n) for n in self.char_vectorizer.get_feature_names_out()]
        if self.use_structural:
            names += [("structural", n) for n in FEATURE_NAMES]
        return names
