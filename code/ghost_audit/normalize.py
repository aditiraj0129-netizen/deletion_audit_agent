"""Small helpers that turn raw identifier strings into comparable tokens.

Every identifier we see in evidence (emails, phones, hashes, user ids, names)
is reduced to a typed token such as ``email:jane@x.com`` or ``phone:4479001``.
Matching evidence to a person then becomes a simple set intersection.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
NULLS = {None, "", "null", "none", "nil", "n/a", "-"}


def is_null(value) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value.strip().lower() in NULLS:
        return True
    return False


def norm_email(value: str) -> str:
    return value.strip().strip('"').lower()


def norm_phone(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def norm_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def token_for(value) -> str | None:
    """Classify a single identifier value into a typed token."""
    if is_null(value):
        return None
    s = str(value).strip().strip('"')
    if EMAIL_RE.fullmatch(s):
        return "email:" + norm_email(s)
    if re.fullmatch(r"user_\d+", s):
        return "user:" + s
    if HASH_RE.fullmatch(s):
        return "hash:" + s.lower()
    digits = norm_phone(s)
    if s.startswith("+") and len(digits) >= 7:
        return "phone:" + digits
    return None


def tokens_in_text(text: str) -> set[str]:
    """Pull every identifier-looking token out of free text."""
    out: set[str] = set()
    if not text:
        return out
    for m in EMAIL_RE.findall(text):
        out.add("email:" + norm_email(m))
    for m in USER_RE.findall(text):
        out.add("user:" + m)
    for m in HASH_RE.findall(text):
        out.add("hash:" + m.lower())
    for m in re.findall(r"\+\d[\d\s().\-]{6,}\d", text):
        out.add("phone:" + norm_phone(m))
    return out


def parse_ts(value: str) -> datetime:
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
