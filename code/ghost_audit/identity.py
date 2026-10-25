"""Identity resolution: request e-mail -> stable user_id -> every identifier the
person has ever used (current snapshot + audit-log history)."""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field

from .normalize import norm_email, norm_name, norm_phone, parse_ts, token_for


@dataclass
class Identity:
    user_id: str | None
    request_email: str
    tokens: set = field(default_factory=set)        # strong link tokens
    names: set = field(default_factory=set)         # weak (display names)
    current: dict = field(default_factory=dict)
    history: list = field(default_factory=list)     # audit rows used
    matched_via: str = ""

    def strong_tokens(self) -> set:
        return {t for t in self.tokens if not t.startswith("name:")}


class IdentityResolver:
    def __init__(self, dataset_dir: str):
        self.users = {}
        for r in csv.DictReader(open(os.path.join(dataset_dir, "user_identities.csv"), encoding="utf-8")):
            self.users[r["user_id"]] = r
        self.audit = list(csv.DictReader(open(os.path.join(dataset_dir, "user_audit_log.csv"), encoding="utf-8")))
        self.by_email_current = {}
        for uid, r in self.users.items():
            self.by_email_current.setdefault(norm_email(r["email"]), set()).add(uid)
        self.by_email_hist = {}
        for a in self.audit:
            if a["field_name"] == "email":
                for v in (a["old_value"], a["new_value"]):
                    self.by_email_hist.setdefault(norm_email(v), set()).add(a["user_id"])

    def resolve(self, email: str, audit_at=None) -> Identity:
        e = norm_email(email)
        uids = self.by_email_current.get(e, set())
        via = "current_email"
        if not uids:
            uids = self.by_email_hist.get(e, set())
            via = "historical_email"
        if len(uids) != 1:
            ident = Identity(None, e, {"email:" + e}, matched_via="unresolved" if not uids else "ambiguous")
            return ident
        uid = next(iter(uids))
        cur = self.users.get(uid, {})
        ident = Identity(uid, e, set(), set(), dict(cur), [], via)
        ident.tokens.add("user:" + uid)
        ident.tokens.add("email:" + e)
        for k in ("email", "phone", "email_hash"):
            t = token_for(cur.get(k))
            if t:
                ident.tokens.add(t)
        if cur.get("name"):
            ident.names.add(norm_name(cur["name"]))
        for a in self.audit:
            if a["user_id"] != uid:
                continue
            ident.history.append(a)
            for v in (a["old_value"], a["new_value"]):
                if a["field_name"] == "name":
                    ident.names.add(norm_name(v))
                    continue
                t = token_for(v)
                if t is None and a["field_name"] == "phone":
                    d = norm_phone(v)
                    t = "phone:" + d if d else None
                if t:
                    ident.tokens.add(t)
        return ident
