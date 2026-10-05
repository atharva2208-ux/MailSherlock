import numpy as np

from ml.features.structural import FEATURE_NAMES, extract_structural
from ml.preprocessing.dedupe import group_ids, near_duplicate_pairs
from ml.preprocessing.email_text import normalise_text, parse_email
from ml.preprocessing.preprocess import assign_splits, is_english


def test_parse_email_decodes_mime_and_extracts_html_structure(sample_bytes):
    parsed = parse_email(sample_bytes("phishing/credential-harvest.eml"))
    assert parsed.subject.startswith("Mailbox storage quota exceeded")
    assert parsed.form_count == 1 and parsed.password_inputs == 1
    assert "sign in below" in parsed.body


def test_parse_email_never_raises_on_garbage():
    for raw in (b"", b"\xff\xfe\x00garbage", b"Content-Type: multipart/mixed; boundary=x\n\n--x\n"):
        parsed = parse_email(raw)
        assert isinstance(parsed.body, str)


def test_normalise_masks_identifiers_and_scrubs_corpus_artefacts():
    text = normalise_text(
        "Re: [ILUG] Invoice 4471",
        "Dear phishing@pot, pay $5,000 at https://evil.example/x or mail bob@corp.example\n"
        "> quoted reply line\nOn Tue, Alice wrote:\nURL: http://feed.example/1",
    )
    assert "phishing" not in text and "pot" not in text
    assert "ilug" not in text and not text.startswith("re")
    assert "urltoken" in text and "emailtoken" in text
    assert "4471" not in text and "5,000" not in text
    assert "quoted reply" not in text and "wrote" not in text


def test_structural_features_capture_url_tricks(sample_bytes):
    features = dict(zip(FEATURE_NAMES, extract_structural(parse_email(sample_bytes("phishing/paypal-alert.eml")))))
    assert features["ip_url"] == 1.0
    assert features["at_symbol_url"] == 1.0
    assert features["shortener_url"] == 1.0
    assert features["anchor_domain_mismatch"] == 1.0


def test_structural_features_tolerate_malformed_urls():
    raw = b"Subject: x\nContent-Type: text/plain\n\nhttp://[bit.ly http://%%% https:// www."
    vector = extract_structural(parse_email(raw))
    assert vector.shape == (len(FEATURE_NAMES),) and np.isfinite(vector).all()


def test_near_duplicate_grouping_links_template_variants():
    texts = [
        "your parcel 123 is waiting, pay the customs fee of 2 usd at the link below today",
        "your parcel 987 is waiting, pay the customs fee of 3 usd at the link below today",
        "minutes from the linux users group meeting on kernel scheduling and filesystems",
    ]
    groups = group_ids(len(texts), near_duplicate_pairs(texts, 0.6))
    assert groups[0] == groups[1] != groups[2]


def test_group_split_never_divides_a_group_and_stays_stratified():
    labels = ["phishing"] * 60 + ["legitimate"] * 40
    groups = {i: [i] for i in range(100)}
    groups[0] = [0, 1, 2, 3]
    for i in (1, 2, 3):
        del groups[i]
    assignment = assign_splits(groups, labels, seed=7)
    assert set(assignment.values()) == {"train", "validation", "test"}
    for label in ("phishing", "legitimate"):
        counts = {s: sum(len(groups[g]) for g, sp in assignment.items() if sp == s and labels[groups[g][0]] == label) for s in ("train", "test")}
        assert counts["train"] > counts["test"] > 0


def test_language_filter():
    assert is_english("please verify your account details and confirm the payment to keep your service active")
    assert not is_english("bitte bestätigen sie ihr konto und die zahlung um den dienst aktiv zu halten danke")
