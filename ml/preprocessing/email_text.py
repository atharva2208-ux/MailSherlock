"""Turn a raw RFC 5322 message into the representation the model consumes.

Training and inference both go through :func:`parse_email` and
:func:`normalise_text`, so the model never sees a representation at serving
time that differs from the one it was trained on.
"""

from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from html.parser import HTMLParser

from ml.config import MAX_BODY_CHARS

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"'()\[\]{}]+""")
EMAIL_RE = re.compile(r"[\w.+%=-]+@[\w-]+(?:\.[\w-]+)+")
NUMBER_RE = re.compile(r"\d+(?:[.,:/-]\d+)*")
WHITESPACE_RE = re.compile(r"\s+")

# Corpus artefacts. phishing_pot replaces recipient addresses with
# ``phishing@pot`` (sometimes truncated or glued to neighbouring characters);
# left in place, the model would learn the dataset rather than phishing.
CORPUS_ARTEFACT_RES = (
    re.compile(r"[\w.+=-]*phish(?:ing)?[\w.]*@[\w.-]*", re.IGNORECASE),
    re.compile(r"phish\.me\.again", re.IGNORECASE),
    re.compile(r"\bphishing@p\w*", re.IGNORECASE),
)
# Mailman footers are a near-perfect marker of 2002-era mailing-list ham.
MAILING_LIST_FOOTER_RE = re.compile(
    r"_{10,}\s*\n.*?(?:mailing list|listinfo|lists?\.[\w.-]+/).*", re.IGNORECASE | re.DOTALL
)

# Conversation scaffolding: quoted replies, attribution lines, forwarded
# header blocks and reply/forward subject prefixes. In the training data these
# are near-perfect markers of 2002 mailing-list ham, so the model learned
# "looks like a list thread => legitimate" instead of anything about phishing.
QUOTED_LINE_RE = re.compile(r"(?m)^\s*(?:>|\|).*$")
ATTRIBUTION_RE = re.compile(r"(?im)^.{0,120}\bwrote:\s*$")
INLINE_HEADER_RE = re.compile(r"(?im)^\s*(?:url|date|from|to|cc|sent|subject|reply-to)\s*:.*$")
SUBJECT_PREFIX_RE = re.compile(r"(?i)^\s*(?:(?:re|fwd?|aw|sv|tr|enc)\s*(?:\[\d+\])?\s*:\s*)+")
# Mailing-list subject tags such as "[ILUG]" or "[zzzzteana]".
LIST_TAG_RE = re.compile(r"\[[A-Za-z0-9_.-]{2,24}\]")
SIGNATURE_DELIMITER_RE = re.compile(r"(?ms)^-- \n.*")

HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?\b|opacity\s*:\s*0(?:\.0+)?\b",
    re.IGNORECASE,
)


@dataclass
class Anchor:
    href: str
    text: str


@dataclass
class ParsedEmail:
    subject: str = ""
    text: str = ""
    html: str = ""
    anchors: list[Anchor] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    attachment_names: list[str] = field(default_factory=list)
    form_count: int = 0
    password_inputs: int = 0
    hidden_elements: int = 0
    script_tags: int = 0
    parse_error: str | None = None

    @property
    def body(self) -> str:
        """Visible text: the plain part, or text rendered from HTML."""
        return self.text if self.text.strip() else html_to_text(self.html).text


class _HtmlExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self.anchors: list[Anchor] = []
        self.forms = 0
        self.password_inputs = 0
        self.hidden = 0
        self.scripts = 0
        self._skip_depth = 0
        self._anchor_href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style", "head", "title"):
            self._skip_depth += 1
            if tag == "script":
                self.scripts += 1
            return
        if HIDDEN_STYLE_RE.search(attributes.get("style", "")) or "hidden" in attributes:
            self.hidden += 1
        if tag == "a" and attributes.get("href"):
            self._anchor_href = attributes["href"].strip()
            self._anchor_text = []
        elif tag == "form":
            self.forms += 1
        elif tag == "input" and attributes.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3", "td"):
            self.chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "head", "title"):
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag == "a" and self._anchor_href is not None:
            self.anchors.append(Anchor(self._anchor_href, " ".join(self._anchor_text).strip()))
            self._anchor_href = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.chunks.append(data)
        if self._anchor_href is not None:
            self._anchor_text.append(data.strip())

    @property
    def text(self) -> str:
        return WHITESPACE_RE.sub(" ", "".join(self.chunks)).strip()


def html_to_text(html: str) -> _HtmlExtractor:
    extractor = _HtmlExtractor()
    try:
        extractor.feed(html)
        extractor.close()
    except Exception:  # malformed markup must never abort parsing
        pass
    return extractor


def _decode_part(part: Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:  # unknown charset label
        return payload.decode("utf-8", errors="replace")


def _parse_message(raw: bytes) -> Message:
    try:
        return email.message_from_bytes(raw, policy=policy.default)
    except Exception:
        return email.message_from_bytes(raw, policy=policy.compat32)


def parse_email(raw: bytes) -> ParsedEmail:
    parsed = ParsedEmail()
    try:
        message = _parse_message(raw)
        try:
            parsed.subject = str(message.get("Subject", "") or "")
        except Exception:
            parsed.subject = ""

        plain: list[str] = []
        html: list[str] = []
        for part in message.walk():
            if part.is_multipart():
                continue
            filename = part.get_filename()
            disposition = (part.get("Content-Disposition") or "").lower()
            if filename or disposition.startswith("attachment"):
                parsed.attachment_names.append(str(filename or ""))
                continue
            content_type = part.get_content_type()
            if content_type == "text/plain":
                plain.append(_decode_part(part))
            elif content_type == "text/html":
                html.append(_decode_part(part))
        parsed.text = "\n".join(plain)
        parsed.html = "\n".join(html)
    except Exception as exc:  # pragma: no cover - defensive
        parsed.parse_error = type(exc).__name__

    if parsed.html:
        extracted = html_to_text(parsed.html)
        parsed.anchors = extracted.anchors
        parsed.form_count = extracted.forms
        parsed.password_inputs = extracted.password_inputs
        parsed.hidden_elements = extracted.hidden
        parsed.script_tags = extracted.scripts

    seen: set[str] = set()
    candidates = [a.href for a in parsed.anchors] + URL_RE.findall(parsed.text)
    for url in candidates:
        url = url.strip().rstrip(".,;:!?")
        if url.lower().startswith(("http://", "https://", "www.")) and url not in seen:
            seen.add(url)
            parsed.urls.append(url)
    return parsed


def scrub_corpus_artefacts(text: str) -> str:
    for pattern in CORPUS_ARTEFACT_RES:
        text = pattern.sub(" ", text)
    text = MAILING_LIST_FOOTER_RE.sub(" ", text)
    text = SIGNATURE_DELIMITER_RE.sub(" ", text)
    for pattern in (QUOTED_LINE_RE, ATTRIBUTION_RE, INLINE_HEADER_RE):
        text = pattern.sub(" ", text)
    return text


def normalise_text(subject: str, body: str) -> str:
    """Model input text: masked, lower-cased, length-bounded.

    URLs, addresses and numbers are masked so the vocabulary captures how a
    message is written rather than which specific hosts, people or dates it
    mentions. Those are handled by structural features and the rule engine.
    """
    text = f"{LIST_TAG_RE.sub(' ', SUBJECT_PREFIX_RE.sub('', subject))}\n{body}"[: MAX_BODY_CHARS * 2]
    text = scrub_corpus_artefacts(text)
    text = URL_RE.sub(" urltoken ", text)
    text = EMAIL_RE.sub(" emailtoken ", text)
    text = NUMBER_RE.sub(" 0 ", text)
    text = WHITESPACE_RE.sub(" ", text).strip().lower()
    return text[:MAX_BODY_CHARS]
