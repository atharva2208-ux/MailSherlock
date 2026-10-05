"""Stage 1: raw corpora -> validated, de-duplicated, grouped train/validation/test splits.

Usage::

    python3 -m ml.preprocessing.preprocess
"""

from __future__ import annotations

import json
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

from ml.config import (
    DATASET_VERSION,
    NEAR_DUPLICATE_SIMILARITY,
    PROCESSED_DIR,
    RANDOM_SEED,
    SPLIT_DIRS,
    SPLIT_FRACTIONS,
)
from ml.datasets.sources import SOURCES, available_sources, iter_raw_emails
from ml.features.pipeline import featurise_raw
from ml.preprocessing.dedupe import content_hash, group_ids, near_duplicate_pairs

MIN_TEXT_CHARS = 40

# The legitimate corpus is English-only. Keeping non-English phishing would
# let the model learn "not English => phishing", a shortcut that inflates
# test metrics and misfires on real multilingual mail. Restricting both
# classes to English removes that confound; multilingual coverage is listed
# as a known limitation instead.
ENGLISH_STOPWORDS = frozenset(
    "the and to of a in is you your for that this it on with are be as at have we our "
    "from or will by not can if an please has was".split()
)
MIN_ENGLISH_RATIO = 0.12


def is_english(text: str) -> bool:
    tokens = [t for t in text.split() if t.isalpha()]
    if len(tokens) < 8:
        return False
    return sum(t in ENGLISH_STOPWORDS for t in tokens) / len(tokens) >= MIN_ENGLISH_RATIO


def assign_splits(groups: dict[int, list[int]], labels: list[str], seed: int) -> dict[int, str]:
    """Allocate whole groups to splits, separately per label (stratified)."""
    rng = random.Random(seed)
    assignment: dict[int, str] = {}
    by_label: dict[str, list[int]] = defaultdict(list)
    for gid, members in groups.items():
        by_label[labels[members[0]]].append(gid)

    for label, gids in sorted(by_label.items()):
        gids.sort()
        rng.shuffle(gids)
        total = sum(len(groups[g]) for g in gids)
        cutoffs = {
            "train": SPLIT_FRACTIONS["train"] * total,
            "validation": (SPLIT_FRACTIONS["train"] + SPLIT_FRACTIONS["validation"]) * total,
        }
        running = 0
        for gid in gids:
            split = "train" if running < cutoffs["train"] else "validation" if running < cutoffs["validation"] else "test"
            assignment[gid] = split
            running += len(groups[gid])
    return assignment


def main() -> int:
    if not available_sources():
        print("No raw corpora found. Run scripts/fetch-datasets.sh first.", file=sys.stderr)
        return 1

    stats: Counter[str] = Counter()
    records: list[dict] = []
    seen_hashes: dict[str, str] = {}

    for item in iter_raw_emails():
        stats[f"loaded_{item.label}"] += 1
        features, parsed = featurise_raw(item.raw)
        if parsed.parse_error:
            stats[f"dropped_unparseable_{item.label}"] += 1
            continue
        if len(features.text) < MIN_TEXT_CHARS:
            stats[f"dropped_empty_{item.label}"] += 1
            continue
        if not is_english(features.text):
            stats[f"dropped_non_english_{item.label}"] += 1
            continue
        digest = content_hash(features.text)
        if digest in seen_hashes:
            key = "label_conflict" if seen_hashes[digest] != item.label else f"dropped_exact_duplicate_{item.label}"
            stats[key] += 1
            continue
        seen_hashes[digest] = item.label
        records.append(
            {
                "id": digest[:16],
                "source": item.source,
                "label": item.label,
                "text": features.text,
                "structural": [round(float(v), 6) for v in features.structural],
            }
        )

    # Near-duplicate grouping runs per label; a cross-label near duplicate
    # is a labelling ambiguity, counted below rather than silently merged.
    labels = [r["label"] for r in records]
    group_of = [0] * len(records)
    for label in sorted(set(labels)):
        indices = [i for i, l in enumerate(labels) if l == label]
        pairs = near_duplicate_pairs([records[i]["text"] for i in indices], NEAR_DUPLICATE_SIMILARITY)
        local_groups = group_ids(len(indices), pairs)
        for local, global_index in enumerate(indices):
            group_of[global_index] = indices[local_groups[local]]
        stats[f"near_duplicate_pairs_{label}"] = len(pairs)

    groups: dict[int, list[int]] = defaultdict(list)
    for i, gid in enumerate(group_of):
        groups[gid].append(i)
    split_of_group = assign_splits(groups, labels, RANDOM_SEED)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    handles = {}
    for name, directory in SPLIT_DIRS.items():
        directory.mkdir(parents=True, exist_ok=True)
        handles[name] = (directory / "emails.jsonl").open("w", encoding="utf-8")

    split_counts: Counter[str] = Counter()
    for i, record in enumerate(records):
        record["group"] = f"g{group_of[i]}"
        split = split_of_group[group_of[i]]
        record["split"] = split
        handles[split].write(json.dumps(record) + "\n")
        split_counts[f"{split}_{record['label']}"] += 1
    for handle in handles.values():
        handle.close()

    manifest = {
        "dataset_version": DATASET_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": RANDOM_SEED,
        "near_duplicate_similarity": NEAR_DUPLICATE_SIMILARITY,
        "sources": [
            {"name": s.name, "label": s.label, "url": s.url, "license": s.license, "description": s.description}
            for s in SOURCES
        ],
        "stats": dict(sorted(stats.items())),
        "groups": len(groups),
        "multi_message_groups": sum(1 for m in groups.values() if len(m) > 1),
        "splits": dict(sorted(split_counts.items())),
        "kept": len(records),
    }
    (PROCESSED_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
