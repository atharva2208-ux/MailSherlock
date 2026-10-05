from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


@pytest.fixture
def sample_bytes():
    def load(name: str) -> bytes:
        return (SAMPLES / name).read_bytes()

    return load
