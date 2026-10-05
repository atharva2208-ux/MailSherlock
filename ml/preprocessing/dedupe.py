"""Exact and near-duplicate detection used to build leakage-free splits."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors


class UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a: int, b: int) -> None:
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self.parent[max(root_a, root_b)] = min(root_a, root_b)


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def near_duplicate_pairs(texts: Sequence[str], threshold: float) -> list[tuple[int, int]]:
    """Index pairs whose shingle TF-IDF cosine similarity is >= ``threshold``.

    Character 5-gram shingles are robust to the small token substitutions
    campaigns use to evade exact-match filters (names, amounts, tracking IDs).
    """
    if len(texts) < 2:
        return []
    vectors = TfidfVectorizer(analyzer="char_wb", ngram_range=(5, 5), min_df=2, dtype=np.float32).fit_transform(
        [t[:3000] for t in texts]
    )
    index = NearestNeighbors(metric="cosine", algorithm="brute", radius=1.0 - threshold).fit(vectors)
    _, neighbours = index.radius_neighbors(vectors, return_distance=True)
    pairs: list[tuple[int, int]] = []
    for i, row in enumerate(neighbours):
        for j in row:
            if j > i:
                pairs.append((i, int(j)))
    return pairs


def group_ids(size: int, pairs: Sequence[tuple[int, int]]) -> list[int]:
    finder = UnionFind(size)
    for a, b in pairs:
        finder.union(a, b)
    return [finder.find(i) for i in range(size)]
