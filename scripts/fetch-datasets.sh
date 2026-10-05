#!/usr/bin/env bash
# Acquire the public training corpora into data/raw/.
#
# The corpora are not redistributed with MailSherlock. phishing_pot is
# CC BY-NC 4.0 (non-commercial use, attribution required); the SpamAssassin
# public corpus is distributed under Apache-2.0 by the stdlib-js mirror.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${MAILSHERLOCK_DATASET_CACHE:-$ROOT/data/.cache}"
mkdir -p "$CACHE"

clone() { # <repo-url> <dir>
  if [[ -d "$CACHE/$2/.git" ]]; then
    echo "• using cached $2"
  else
    echo "• cloning $1"
    git -c gc.auto=0 clone --depth 1 --quiet "$1" "$CACHE/$2"
  fi
}

clone https://github.com/rf-peixoto/phishing_pot.git phishing_pot
clone https://github.com/stdlib-js/datasets-spam-assassin.git spamassassin

PHISH="$ROOT/data/raw/phishing/phishing_pot"
HAM="$ROOT/data/raw/legitimate/spamassassin_ham"
rm -rf "$PHISH" "$HAM"
mkdir -p "$PHISH" "$HAM"

cp "$CACHE"/phishing_pot/email/*.eml "$PHISH"/
for folder in easy-ham-1 easy-ham-2 hard-ham-1; do
  mkdir -p "$HAM/$folder"
  cp "$CACHE"/spamassassin/data/"$folder"/*.txt "$HAM/$folder"/
done

echo
echo "phishing:   $(find "$PHISH" -type f | wc -l) messages -> $PHISH"
echo "legitimate: $(find "$HAM" -type f | wc -l) messages -> $HAM"
echo "Next: python3 -m ml.preprocessing.preprocess"
