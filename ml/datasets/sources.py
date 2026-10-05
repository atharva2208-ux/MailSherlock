"""Registry of the public corpora MailSherlock is trained on.

The raw files are never committed. ``scripts/fetch-datasets.sh`` acquires
them into ``data/raw/<label>/<source>/``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from ml.config import MAX_EMAIL_BYTES, RAW_DIR


@dataclass(frozen=True)
class DatasetSource:
    name: str
    label: str
    url: str
    license: str
    description: str
    glob: str


SOURCES: tuple[DatasetSource, ...] = (
    DatasetSource(
        name="phishing_pot",
        label="phishing",
        url="https://github.com/rf-peixoto/phishing_pot",
        license="CC BY-NC 4.0",
        description="Real phishing and scam emails collected from honeypot inboxes (2022-present), "
        "recipient addresses anonymised by the maintainers.",
        glob="*.eml",
    ),
    DatasetSource(
        name="spamassassin_ham",
        label="legitimate",
        url="https://github.com/stdlib-js/datasets-spam-assassin (SpamAssassin public corpus)",
        license="Apache-2.0 (corpus distributed by the Apache SpamAssassin project)",
        description="easy_ham, easy_ham_2 and hard_ham folders: personal, mailing-list, "
        "newsletter and commercial mail that is not spam.",
        glob="*.txt",
    ),
)


@dataclass(frozen=True)
class RawEmail:
    source: str
    label: str
    path: Path
    raw: bytes


def iter_raw_emails(raw_dir: Path = RAW_DIR) -> Iterator[RawEmail]:
    """Yield every raw email found for the registered sources.

    Oversized files are skipped rather than truncated: a truncated MIME body
    parses into misleading text.
    """
    for source in SOURCES:
        directory = raw_dir / source.label / source.name
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob(source.glob)):
            if path.stat().st_size > MAX_EMAIL_BYTES:
                continue
            yield RawEmail(source.name, source.label, path, path.read_bytes())


def available_sources(raw_dir: Path = RAW_DIR) -> list[DatasetSource]:
    return [s for s in SOURCES if (raw_dir / s.label / s.name).is_dir()]
