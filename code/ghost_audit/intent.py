"""Does the request text actually authorise deletion?

Layer 1 is a transparent multilingual rule set (fast, free, deterministic).
Layer 2 is an optional LLM call, used only when the rules are not confident
(no clear deletion verb, or deletion words mixed with "keep"/"don't delete"
style constraints).  The LLM is off unless ANTHROPIC_API_KEY is set.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

# Phrases that mean the person explicitly does NOT want deletion.
NEGATIVE_PATTERNS = [
    r"not (asking|requesting) (for )?(a )?delet", r"not a request to (erase|delete)",
    r"(don'?t|do not|please don'?t) (delete|close|remove|erase)",
    r"without (removing|deleting)", r"leave (the|my) (account|profile)",
    r"keep the account", r"continue using", r"still (want|need|use)",
    r"marketing lists? only", r"stop the promotional", r"unsubscribe",
    r"(send|give|get|need|want)( me)? a copy", r"download my", r"portable format",
    r"what personal information you hold", r"information request",
    r"(correct|change|update|replace) (it|the|my)", r"misspelled", r"out of date",
    r"reset(ting)? the login", r"can'?t access",
]
# Deletion intent in the languages present in the data (+ a few common ones).
POSITIVE_PATTERNS = [
    r"\b(delete|deleting|deleted|deletion|erase|erased|erasure|remove|removal)\b",
    r"\bclose (my|this|the) account\b", r"\bclosed my account\b",
    r"\b(account|profile)\b[^.?!]*\b(removed|gone|erased)\b",
    r"\bpermanent(ly)? (account[- ])?delet", r"\bforget me\b",
    r"suppression", r"supprim", r"eliminaci[oó]n", r"eliminar", r"exclus[aã]o", r"excluir",
    r"l[oö]sch", r"cancellazione", r"삭제", r"削除", r"消去", r"删除", r"удал",
]


def rule_classify(text: str) -> tuple[bool, float, str]:
    t = (text or "").lower()
    neg = [p for p in NEGATIVE_PATTERNS if re.search(p, t)]
    pos = [p for p in POSITIVE_PATTERNS if re.search(p, t)]
    if neg and not pos:
        return False, 0.95, "non-deletion request: " + neg[0]
    if neg and pos:
        # e.g. "not a request to erase it" or "remove me from marketing lists only"
        return False, 0.7, "deletion words are negated/limited: " + neg[0]
    if pos:
        return True, 0.95, "deletion requested: " + pos[0]
    return False, 0.5, "no deletion intent found"


def llm_classify(text: str) -> tuple[bool, str] | None:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    model = os.environ.get("GHOST_AUDIT_MODEL", "claude-haiku-4-5")
    prompt = (
        "You classify privacy requests sent to an online shop. Answer with JSON "
        '{"deletion": true|false, "reason": "..."}. deletion=true only if the '
        "person asks to delete/erase/close their account or personal data. Access, "
        "export, correction, login help, marketing opt-out are NOT deletion.\n\n"
        f"Request: {text}")
    body = json.dumps({"model": model, "max_tokens": 120,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        USAGE.record(model, data.get("usage", {}))
        out = data["content"][0]["text"]
        m = re.search(r"\{.*\}", out, re.S)
        js = json.loads(m.group(0)) if m else {}
        return bool(js.get("deletion")), "llm: " + str(js.get("reason", ""))[:120]
    except Exception:
        return None


class _Usage:
    def __init__(self):
        self.calls = {}

    def record(self, model, usage):
        c = self.calls.setdefault(model, {"calls": 0, "input_tokens": 0, "output_tokens": 0})
        c["calls"] += 1
        c["input_tokens"] += int(usage.get("input_tokens", 0))
        c["output_tokens"] += int(usage.get("output_tokens", 0))


USAGE = _Usage()


def classify(text: str, use_llm: bool = True) -> tuple[bool, str]:
    is_del, conf, why = rule_classify(text)
    if conf < 0.9 and use_llm:
        llm = llm_classify(text)
        if llm is not None:
            return llm
    return is_del, why
