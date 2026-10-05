"""Hand-engineered structural features.

These deliberately exclude header-derived signals (SPF/DKIM/DMARC, Received
chain, X-Mailer). In the training corpora those headers encode *which dataset
and which decade* a message came from rather than whether it is phishing, so a
model trained on them would look excellent in evaluation and fail in
production. Header forensics is the rule engine's job.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import unquote, urlsplit

import numpy as np

from ml.preprocessing.email_text import ParsedEmail

SUSPICIOUS_TLDS = frozenset(
    "top xyz icu tk ml ga cf gq buzz cyou rest click link work fit shop live loan zip mov "
    "monster sbs cfd quest bond lol support country kim".split()
)
SHORTENERS = frozenset(
    "bit.ly t.co tinyurl.com goo.gl ow.ly is.gd buff.ly rebrand.ly cutt.ly shorturl.at "
    "rb.gy t.ly tiny.cc s.id lnkd.in".split()
)
CREDENTIAL_PATH_RE = re.compile(
    r"(?i)(log-?in|sign-?in|verify|verification|account|secure|update|webscr|password|"
    r"auth|wp-(?:admin|includes|content)|\.php\b|confirm|unlock|validate)"
)
DANGEROUS_EXTENSIONS = frozenset(
    "exe scr js jse vbs vbe ps1 bat cmd com iso img lnk hta msi jar wsf cpl reg dll".split()
)
URGENCY_RE = re.compile(
    r"(?i)\b(urgent|immediately|within \d+ hours?|asap|final notice|suspend|"
    r"expire[sd]?|deactivat|locked|limited|right away|act now)\b"
)
CREDENTIAL_RE = re.compile(
    r"(?i)\b(password|passcode|credentials?|log ?in|sign ?in|verify your|"
    r"confirm your|security code|one[- ]time code|ssn|social security)\b"
)

FEATURE_NAMES: tuple[str, ...] = (
    "url_count_log",
    "unique_domain_count",
    "ip_url",
    "at_symbol_url",
    "shortener_url",
    "suspicious_tld_ratio",
    "punycode_domain",
    "max_url_length_log",
    "max_subdomain_depth",
    "credential_path_ratio",
    "encoded_url",
    "anchor_domain_mismatch",
    "max_hostname_entropy",
    "form_present",
    "password_input",
    "hidden_elements",
    "script_present",
    "attachment_count",
    "dangerous_attachment",
    "double_extension_attachment",
    "body_length_log",
    "uppercase_ratio",
    "exclamation_rate",
    "urgency_terms",
    "credential_terms",
)

HUMAN_NAMES = {
    "url_count_log": "Number of links",
    "unique_domain_count": "Distinct link domains",
    "ip_url": "Link to a raw IP address",
    "at_symbol_url": "'@' inside a URL",
    "shortener_url": "URL shortener",
    "suspicious_tld_ratio": "Links on high-abuse TLDs",
    "punycode_domain": "Punycode (IDN) domain",
    "max_url_length_log": "Very long URL",
    "max_subdomain_depth": "Deep subdomain nesting",
    "credential_path_ratio": "Login/verify-style URL paths",
    "encoded_url": "Percent-encoded URL",
    "anchor_domain_mismatch": "Link text shows a different domain",
    "max_hostname_entropy": "Random-looking hostname",
    "form_present": "Embedded HTML form",
    "password_input": "Password field in email",
    "hidden_elements": "Hidden HTML elements",
    "script_present": "Script tags",
    "attachment_count": "Attachments",
    "dangerous_attachment": "Executable/script attachment",
    "double_extension_attachment": "Double-extension filename",
    "body_length_log": "Message length",
    "uppercase_ratio": "Uppercase emphasis",
    "exclamation_rate": "Exclamation marks",
    "urgency_terms": "Urgency language",
    "credential_terms": "Credential-related language",
}


def _netloc(url: str) -> str:
    """Authority component without raising: phishing URLs are routinely malformed."""
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        return urlsplit(url).netloc
    except ValueError:
        match = re.match(r"(?i)[a-z][a-z0-9+.-]*://([^/?#]*)", url)
        return match.group(1) if match else ""


def _hostname(url: str) -> str:
    host = _netloc(url).rsplit("@", 1)[-1]
    if host.startswith("["):
        return host.split("]", 1)[0].strip("[").lower()
    return host.split(":", 1)[0].lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _registrable(host: str) -> str:
    """Approximate registrable domain (last two labels).

    Adequate for a feature; the rule engine uses the full Public Suffix List.
    """
    parts = [p for p in host.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


DOMAIN_IN_TEXT_RE = re.compile(r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b")


def extract_structural(parsed: ParsedEmail) -> np.ndarray:
    urls = parsed.urls
    hosts = [_hostname(u) for u in urls]
    hosts_nonempty = [h for h in hosts if h]
    n_urls = len(urls)

    anchor_mismatch = 0
    for anchor in parsed.anchors:
        shown = DOMAIN_IN_TEXT_RE.search(anchor.text or "")
        href_host = _hostname(anchor.href)
        if shown and href_host:
            if _registrable(shown.group(1).lower()) != _registrable(href_host):
                anchor_mismatch = 1
                break

    attachments = [n.lower() for n in parsed.attachment_names if n]
    extensions = [n.rsplit(".", 1)[-1] for n in attachments if "." in n]
    double_ext = any(
        len(n.split(".")) >= 3 and n.rsplit(".", 1)[-1] in DANGEROUS_EXTENSIONS for n in attachments
    )

    body = parsed.body[:20000]
    letters = [c for c in body if c.isalpha()]
    words = max(1, len(body.split()))

    def ratio(flags: list[bool]) -> float:
        return sum(flags) / len(flags) if flags else 0.0

    values = {
        "url_count_log": math.log1p(n_urls),
        "unique_domain_count": float(min(len({_registrable(h) for h in hosts_nonempty}), 20)),
        "ip_url": float(any(_is_ip(h) for h in hosts_nonempty)),
        "at_symbol_url": float(any("@" in _netloc(u) for u in urls)),
        "shortener_url": float(any(h in SHORTENERS for h in hosts_nonempty)),
        "suspicious_tld_ratio": ratio([h.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS for h in hosts_nonempty]),
        "punycode_domain": float(any("xn--" in h for h in hosts_nonempty)),
        "max_url_length_log": math.log1p(max((len(u) for u in urls), default=0)),
        "max_subdomain_depth": float(min(max((h.count(".") for h in hosts_nonempty), default=0), 8)),
        "credential_path_ratio": ratio([bool(CREDENTIAL_PATH_RE.search(unquote(u))) for u in urls]),
        "encoded_url": float(any(re.search(r"%[0-9a-fA-F]{2}", u) for u in urls)),
        "anchor_domain_mismatch": float(anchor_mismatch),
        "max_hostname_entropy": max((_entropy(h.split(".")[0]) for h in hosts_nonempty), default=0.0),
        "form_present": float(parsed.form_count > 0),
        "password_input": float(parsed.password_inputs > 0),
        "hidden_elements": float(min(parsed.hidden_elements, 10)),
        "script_present": float(parsed.script_tags > 0),
        "attachment_count": float(min(len(parsed.attachment_names), 10)),
        "dangerous_attachment": float(any(e in DANGEROUS_EXTENSIONS for e in extensions)),
        "double_extension_attachment": float(double_ext),
        "body_length_log": math.log1p(len(body)),
        "uppercase_ratio": sum(c.isupper() for c in letters) / len(letters) if letters else 0.0,
        "exclamation_rate": body.count("!") / words,
        "urgency_terms": float(min(len(URGENCY_RE.findall(body)), 10)),
        "credential_terms": float(min(len(CREDENTIAL_RE.findall(body)), 10)),
    }
    return np.array([values[name] for name in FEATURE_NAMES], dtype=np.float64)
