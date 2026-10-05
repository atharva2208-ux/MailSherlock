# Dataset

## Sources

| Name                             | Class      | URL                                                 | Licence      | Notes                                                                                                                 |
| -------------------------------- | ---------- | --------------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------- |
| phishing_pot                     | phishing   | https://github.com/rf-peixoto/phishing_pot          | CC BY-NC 4.0 | Real phishing and scam email captured in honeypot inboxes, 2022 onward; recipients anonymised as `phishing@pot`       |
| SpamAssassin public corpus (ham) | legitimate | https://github.com/stdlib-js/datasets-spam-assassin | Apache-2.0   | easy_ham, easy_ham_2, hard_ham (2002); personal mail, mailing lists, newsletters and commercial mail that is not spam |

Neither corpus is committed. `scripts/fetch-datasets.sh` clones both into `data/raw/<label>/<source>/`. Never add private mailbox data to `data/`; the directory is git-ignored for that reason.

## Preprocessing results (`data/processed/manifest.json`)

| Step                         | Phishing  | Legitimate |
| ---------------------------- | --------- | ---------- |
| Loaded                       | 8,606     | 4,150      |
| Dropped: empty after parsing | 79        | 18         |
| Dropped: not English         | 4,342     | 152        |
| Dropped: exact duplicates    | 991       | 61         |
| **Kept**                     | **3,194** | **3,919**  |

Near-duplicate grouping produced 5,408 groups, 381 of which contain more than one message.

| Split      | Phishing | Legitimate |
| ---------- | -------- | ---------- |
| Train      | 2,239    | 2,761      |
| Validation | 507      | 571        |
| Test       | 448      | 587        |

## Leakage controls

- **Grouped splits.** Messages whose normalised text has character 5-gram TF-IDF cosine similarity ≥ 0.80 are joined by union-find. Whole groups are assigned to a split, stratified by class, so a campaign template cannot appear in both train and test.
- **Exact deduplication** on the normalised text hash, before grouping.
- **Corpus artefact scrubbing.** The `phishing@pot` placeholder (including truncated forms), mailing-list footers and `[list]` subject tags, quoted reply lines, `… wrote:` attributions, forwarded header blocks and `Re:`/`Fwd:` prefixes are removed from both classes.
- **No header features in the model.** Authentication results, Received chains and mailer headers identify the source corpus and its era.
- **Language restriction** to English, removing a class-correlated language signal.
- **Global-weight audit.** Every training run writes the strongest coefficients to `report.md`. That audit is how the conversational and list-tag artefacts above were found and removed.

## Limitations

- The legitimate corpus is from 2002 and lacks modern transactional mail. This is the main cause of the classifier's false positives on the challenge set.
- phishing_pot includes scam and spam-style lures as well as credential phishing; the classifier learns "phishing or scam" vs "legitimate".
- After language filtering the phishing class is about 3,200 messages. That is enough for a linear text model, but not for a transformer to show a measurable benefit.

## Challenge set

`ml/datasets/challenge/challenge.jsonl` contains 34 short, fictional, hand-written modern emails (22 legitimate, 12 phishing). It is used only for evaluation, never for training or threshold selection. It was inspected during development of the false-positive controls, so it serves as a regression check rather than an untouched hold-out.
