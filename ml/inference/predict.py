"""Stage 4: command-line inference.

Usage::

    python3 -m ml.inference.predict samples/phishing/paypal-alert.eml [...]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ml.inference.predictor import Predictor


def main() -> int:
    parser = argparse.ArgumentParser(description="Score .eml files with the MailSherlock classifier")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true", help="print full JSON output")
    args = parser.parse_args()

    predictor = Predictor.load()
    for path in args.files:
        prediction = predictor.predict_raw(path.read_bytes())
        if args.json:
            print(json.dumps({"file": str(path), **prediction.as_dict()}, indent=2))
        else:
            print(f"{prediction.probability:6.1%}  {prediction.label:10s}  {prediction.confidence:6s}  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
