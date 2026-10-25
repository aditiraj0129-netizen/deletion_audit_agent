"""Evidence extraction: every supplied file becomes a list of `Observation`s.

An observation is one statement of the form "at time T, in system S, resource R
was (present|absent), with these identifier fields and these flags".  All the
different formats (SQL snapshots, JSON bundles, five log dialects, hand-over
text, PDFs and screenshots) are reduced to this single shape so that the rest
of the agent never has to care where a fact came from.

Nothing here knows about cases.  The manifest does not say which case a file
belongs to, so linking happens later through identifier tokens.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime

from .normalize import (EMAIL_RE, is_null, iso, norm_email, norm_name,
                        norm_phone, parse_ts, token_for, tokens_in_text)

# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------
SYSTEM_BY_PREFIX = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "audit_record": "security_service",
    "tombstone": "identity_service",
    "legal_hold": "legal_service",
    "marketing": "marketing_platform",
    "object": "object_storage",
    "cache": "cache_service",
    "email_delivery": "email_delivery_service",
    "telemetry": "telemetry_service",
}
CATEGORY_BY_SYSTEM = {
    "account_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "analytics_platform": "ANALYTICS_PROFILE",
    "support_platform": "SUPPORT_MESSAGE",
    "export_service": "USER_EXPORT",
    "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "security_service": "SECURITY_AUDIT_LOG",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "legal_service": "LEGAL_HOLD_RECORD",
    "marketing_platform": "MARKETING_PROFILE",
    "object_storage": "SUPPORT_ATTACHMENT",
    "cache_service": "CACHE_ENTRY",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
    "telemetry_service": "PRODUCT_TELEMETRY",
}
RESOURCE_RE = re.compile(
    r"\b(account|search|analytics|support|export|data_flow|backup|audit_record|"
    r"tombstone|legal_hold|marketing|object|cache|email_delivery|telemetry)_(\d+)\b")

# identifier columns we understand, mapped onto canonical field names
FIELD_ALIASES = {
    "email": "email", "owner_email": "email", "requester_email": "email",
    "customer_email": "email", "uploaded_by": "email",
    "phone": "phone", "owner_phone": "phone", "requester_phone": "phone",
    "full_name": "name", "name": "name", "display_name": "name",
    "requester_name": "name",
    "email_hash": "email_hash",
    "customer_reference": "ref", "subject_reference": "ref", "user_id": "ref",
    "subject_ref": "ref",
}
DIRECT_FIELDS = ("email", "phone", "name", "email_hash")


def system_of(resource_id: str) -> str | None:
    m = RESOURCE_RE.fullmatch(resource_id or "")
    if not m:
        return None
    return SYSTEM_BY_PREFIX[m.group(1)]


@dataclass
class Observation:
    evidence_id: str            # file_id or activity_id
    ts: datetime                # when the fact was true
    resource_id: str
    system: str
    category: str
    present: bool | None        # True=exists, False=absent, None=unknown
    fields: dict = field(default_factory=dict)   # canonical field -> value|None
    link_tokens: set = field(default_factory=set)
    flags: dict = field(default_factory=dict)    # enabled / restore_allowed / identifiable / redacted
    source: str = ""            # short description for debugging/explanations

    # -- derived views -------------------------------------------------
    def direct_identifiers(self) -> dict:
        return {k: v for k, v in self.fields.items()
                if k in DIRECT_FIELDS and not is_null(v)}

    def has_direct_identifiers(self) -> bool | None:
        """True/False when the observation shows the identifier columns,
        None when it simply does not tell us."""
        if "identifiable" in self.flags:
            return bool(self.flags["identifiable"])
        known = [k for k in self.fields if k in DIRECT_FIELDS]
        if not known:
            return None
        return bool(self.direct_identifiers())

    def has_reference(self) -> bool | None:
        if "ref" not in self.fields:
            return None
        return not is_null(self.fields["ref"])

    def describe(self) -> str:
        return f"{self.evidence_id}@{iso(self.ts)} {self.resource_id} present={self.present} {self.flags} {self.source}"


def _mk(evidence_id, ts, resource_id, present=True, fields=None, extra_tokens=(),
        flags=None, category=None, system=None, source=""):
    system = system or system_of(resource_id)
    if system is None:
        return None
    fields = {k: v for k, v in (fields or {}).items()}
    toks = set()
    for k, v in fields.items():
        t = token_for(v)
        if t:
            toks.add(t)
        elif k == "name" and not is_null(v):
            toks.add("name:" + norm_name(str(v)))
    for t in extra_tokens:
        if t:
            toks.add(t)
    category = category or CATEGORY_BY_SYSTEM.get(system, "UNKNOWN")
    return Observation(evidence_id, ts, resource_id, system, category, present,
                       fields, toks, dict(flags or {}), source)


def _bool(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    s = str(v).strip().strip('"').lower()
    if s in ("1", "true", "yes", "allowed", "enabled", "active"):
        return True
    if s in ("0", "false", "no", "denied", "deny", "disabled", "blocked", "stopped"):
        return False
    return None


def fields_from_record(rec: dict) -> tuple[dict, set]:
    """Map a raw record onto canonical identifier fields (+ free-text tokens)."""
    fields: dict = {}
    extra: set = set()
    for k, v in rec.items():
        if k == "document" and isinstance(v, dict):
            f2, e2 = fields_from_record(v)
            fields.update(f2)
            extra |= e2
            continue
        canon = FIELD_ALIASES.get(k)
        if canon:
            if canon == "ref" and isinstance(v, str) and "@" in v:
                fields["email"] = v
            else:
                fields[canon] = None if is_null(v) else v
        elif k == "subject_selector":
            # connectors select by user id or by e-mail
            if isinstance(v, str) and "@" in v:
                fields["email"] = v
            else:
                fields["ref"] = None if is_null(v) else v
        elif k == "lookup_value":
            t = token_for(v)
            if t:
                extra.add(t)
        elif k in ("message_text", "message_excerpt") and isinstance(v, str):
            toks = tokens_in_text(v)
            extra |= toks
            fields["_text"] = v
    return fields, extra


# ---------------------------------------------------------------------------
# Record-level state helpers shared by JSON and SQL sources
# ---------------------------------------------------------------------------
def record_observation(eid, ts, rec: dict, system: str | None = None,
                       collection: str = "", source: str = ""):
    rid = rec.get("resource_id")
    if not rid:
        return None
    system = system_of(rid) or system
    fields, extra = fields_from_record(rec)
    flags = {}
    category = None
    if "enabled" in rec:
        flags["enabled"] = _bool(rec["enabled"])
    if "restore_allowed" in rec:
        flags["restore_allowed"] = _bool(rec["restore_allowed"])
    if "download_available" in rec:
        flags["available"] = _bool(rec["download_available"])
    text = fields.pop("_text", None)
    if text is not None:
        redacted = text.strip().upper() == "[REDACTED]" or not extra
        flags["identifiable"] = bool(extra - {t for t in extra if t.startswith("user:")}) or \
            any(not is_null(fields.get(k)) for k in DIRECT_FIELDS)
        flags["redacted"] = redacted and not flags["identifiable"]
    if collection == "ticket_attachments" or rec.get("storage_class") == "ticket_attachment":
        category = "SUPPORT_ATTACHMENT"
    if system == "identity_service":
        category = "ACCOUNT_TOMBSTONE"
    if rec.get("account_status") and str(rec.get("account_status")).upper() == "DELETED" \
            and system == "account_service":
        # a deleted-status row still holding identifiers behaves like a tombstone
        category = "ACCOUNT_TOMBSTONE"
    return _mk(eid, ts, rid, True, fields, extra, flags, category, system, source)


def lookup_observation(eid, ts, system, rid, record_type, result, subject):
    """Rows of the form system | resource | RECORD_TYPE | RESULT | subject."""
    result = (result or "").strip().upper()
    record_type = (record_type or "").strip().upper()
    present = None
    flags = {}
    if result in ("FOUND", "PRESENT", "IDENTIFIABLE", "ACTIVE", "REDACTED",
                  "ANONYMIZED", "BLOCKED", "DISABLED", "RETAINED"):
        present = True
    elif result in ("NOT_FOUND", "ABSENT", "DELETED", "MISSING"):
        present = False
    if result == "IDENTIFIABLE":
        flags["identifiable"] = True
    elif result in ("ANONYMIZED", "REDACTED"):
        flags["identifiable"] = False
        flags["redacted"] = True
    if record_type == "DATA_FLOW":
        if result == "ACTIVE":
            flags["enabled"] = True
        elif result == "DISABLED":
            flags["enabled"] = False
    if record_type == "BACKUP_ARCHIVE":
        if result == "ACTIVE":
            flags["restore_allowed"] = True
        elif result == "BLOCKED":
            flags["restore_allowed"] = False
    tok = token_for(subject)
    category = record_type if record_type and record_type != "DATA_FLOW" else None
    return _mk(eid, ts, rid, present, {}, [tok] if tok else [], flags,
               category, system or None, source=f"lookup {record_type}={result}")


# ---------------------------------------------------------------------------
# Format parsers
# ---------------------------------------------------------------------------
def parse_json_file(eid, path, captured: datetime):
    data = json.load(open(path, encoding="utf-8"))
    out = []

    def ts_of(rec, default):
        for k in ("observed_at", "recorded_at", "captured_at"):
            if rec.get(k):
                try:
                    return parse_ts(rec[k])
                except ValueError:
                    pass
        return default

    if isinstance(data, dict) and "snapshots" in data:
        for snap in data["snapshots"]:
            sts = parse_ts(snap.get("captured_at")) if snap.get("captured_at") else captured
            store = snap.get("data_store")
            coll = snap.get("collection", "")
            recs = snap.get("records", [])
            out.append(("SCOPE", store, sts, coll, [r.get("resource_id") for r in recs]))
            for r in recs:
                if "record_type" in r and "result" in r:
                    o = lookup_observation(eid, ts_of(r, sts), r.get("system"), r.get("resource_id"),
                                           r.get("record_type"), r.get("result"),
                                           r.get("subject_reference") or r.get("lookup_value"))
                else:
                    o = record_observation(eid, sts, r, store, coll, source=f"snapshot {coll}")
                if o:
                    out.append(o)
        return out
    if isinstance(data, dict) and "service_exports" in data:
        for system, colls in data["service_exports"].items():
            for coll, recs in colls.items():
                for r in recs:
                    t = ts_of(r, captured)
                    if coll == "profile_lookups":
                        prof = r.get("profile")
                        code = int(r.get("status_code", 0) or 0)
                        rec = dict(prof or {})
                        rec["resource_id"] = r["resource_id"]
                        o = record_observation(eid, t, rec, system, coll, source="profile_lookup")
                        if o:
                            o.present = code == 200 or bool(prof)
                            if not o.present:
                                o.fields = {}
                                o.link_tokens = set()
                            out.append(o)
                    elif coll == "index_queries":
                        q = token_for(r.get("query"))
                        hits = r.get("hits") or {}
                        docs = hits.get("documents") if isinstance(hits, dict) else hits
                        if docs:
                            for d in docs:
                                o = record_observation(eid, t, d, system, coll, source="index_query hit")
                                if o:
                                    if q:
                                        o.link_tokens.add(q)
                                    out.append(o)
                        elif r.get("resource_id"):
                            o = _mk(eid, t, r["resource_id"], False, {}, [q] if q else [], {},
                                    None, system, "index_query miss")
                            if o:
                                out.append(o)
                    else:
                        o = record_observation(eid, t, r, system, coll, source=coll)
                        if o:
                            out.append(o)
        return out
    records = data.get("records", []) if isinstance(data, dict) else data
    coll = data.get("collection", "") if isinstance(data, dict) else ""
    for r in records:
        if "record_type" in r and "result" in r:
            o = lookup_observation(eid, ts_of(r, captured), r.get("system"), r.get("resource_id"),
                                   r.get("record_type"), r.get("result"),
                                   r.get("subject_reference") or r.get("lookup_value"))
        else:
            o = record_observation(eid, ts_of(r, captured), r, None, coll, source=coll or "json")
        if o:
            out.append(o)
    return out


WHOLE_CAPTURE_SYSTEMS = {"account_service", "search_service", "analytics_platform", "support_platform",
                         "export_service", "integration_service", "backup_service", "security_service",
                         "identity_service", "legal_service"}

SQL_TABLE_SYSTEM = {
    "customer_profiles": "account_service",
    "customer_search_documents": "search_service",
    "search_documents": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}


def parse_sql_file(eid, path, captured: datetime):
    out = []
    con = sqlite3.connect(":memory:")
    con.executescript(open(path, encoding="utf-8").read())
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    scope = {}
    if "snapshot_scope" in tables:
        for sysname, cts in con.execute("select origin_system, captured_at from snapshot_scope"):
            scope[sysname] = parse_ts(cts)
    for t in tables:
        if t == "snapshot_scope":
            continue
        cols = [d[1] for d in con.execute(f'pragma table_info("{t}")')]
        rows = [dict(zip(cols, r)) for r in con.execute(f'select * from "{t}"')]
        if "record_json" in cols:
            seen_sys = {}
            for r in rows:
                rec = json.loads(r["record_json"])
                sysname = r.get("origin_system")
                o = record_observation(eid, captured, rec, sysname, r.get("collection_name", ""),
                                       source=f"sql {t}")
                if o:
                    o.flags["table"] = t
                    out.append(o)
                    seen_sys.setdefault(o.system, []).append(o.resource_id)
            # a full customer-data capture: systems with no rows had no records
            for sysname in WHOLE_CAPTURE_SYSTEMS | set(seen_sys):
                out.append(("SCOPE", sysname, captured, t, seen_sys.get(sysname, [])))
            continue
        base = None
        for prefix, sysname in SQL_TABLE_SYSTEM.items():
            if t.startswith(prefix):
                base = sysname
        sts = scope.get(base, captured)
        rids = []
        for r in rows:
            rec = dict(r)
            if t.startswith("search_documents") and rec.get("source_resource_id"):
                rec.pop("source_resource_id")
            o = record_observation(eid, sts, rec, base, t, source=f"sql {t}")
            if o:
                o.flags["table"] = t
                out.append(o)
                rids.append(o.resource_id)
        if base:
            out.append(("SCOPE", base, sts, t, rids))
    return out


# ---- logs -----------------------------------------------------------------
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("(?:[^"\\]|\\.)*"|[^\s"]+)')
LOOKUP_KEYS = ("lookup_key", "match_key", "subject_key", "scan_key", "owner_key",
               "subject_ref", "correlation_key", "matched_value", "subject_reference",
               "query_key")


def parse_log_line(line: str):
    line = line.rstrip("\n")
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s+(.*)$", line)
    if not m:
        return None
    ts = parse_ts(m.group(1))
    rest = m.group(2)
    kv: dict = {}
    if rest.startswith("{"):
        try:
            kv = {k: str(v) for k, v in json.loads(rest).items()}
        except json.JSONDecodeError:
            return None
        kv.setdefault("service", kv.get("logger", ""))
        return ts, kv
    sm = re.match(r"<\d+>\d+ \S+ (\S+) (\S+) - - (.*)$", rest)          # syslog
    if sm:
        kv["service"], kv["trace_id"] = sm.group(1), sm.group(2)
        rest = sm.group(3)
    bm = re.match(r"\[(\w+)\] \[(\w+)\] \[([\w-]+)\] (\w+): (.*)$", rest)  # bracketed
    if bm:
        kv["level"], kv["service"], kv["trace_id"], kv["event"] = bm.group(1, 2, 3, 4)
        rest = bm.group(5)
    pm = re.match(r"\| (\w+) \| (\w+) \| ([\w-]+) \| (\w+) \| (.*)$", rest)  # pipe
    if pm:
        kv["level"], kv["service"], kv["trace_id"], kv["event"] = pm.group(1, 2, 3, 4)
        rest = pm.group(5)
    cm = re.match(r'requestId=(\S+) level=(\w+) function=(\w+) message="(.*)"$', rest)  # cloud
    if cm:
        kv["trace_id"], kv["level"], kv["service"] = cm.group(1, 2, 3)
        rest = cm.group(4).replace('\\"', '"')
    for k, v in KV_RE.findall(rest):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"')
        kv.setdefault(k, v)
    return ts, kv


def _present_from_kv(kv) -> bool | None:
    ev = kv.get("event", "")
    if "http_status" in kv:
        return kv["http_status"].startswith("2")
    if "rows" in kv:
        try:
            return int(kv["rows"]) > 0
        except ValueError:
            pass
    if kv.get("result") in ("hit", "found", "FOUND"):
        return True
    if kv.get("result") in ("miss", "not_found", "NOT_FOUND"):
        return False
    if "total_hits" in kv:
        return kv["total_hits"] not in ("0",)
    if ev.endswith("_pii_scan") or ev in ("analytics_identity_scan", "message_read"):
        return True
    return True


def parse_log_file(eid, path, captured: datetime):
    out = []
    lines = [p for p in (parse_log_line(l) for l in open(path, encoding="utf-8")) if p]
    trace_keys: dict = {}
    for ts, kv in lines:
        tid = kv.get("trace_id")
        if not tid:
            continue
        for k in LOOKUP_KEYS:
            if k in kv and not is_null(kv[k]):
                t = token_for(kv[k])
                if t:
                    trace_keys.setdefault(tid, set()).add(t)
    for ts, kv in lines:
        ev = kv.get("event", "")
        rid = kv.get("resource_id")
        # record_lookup style rows (hand-over / delivery logs)
        if ev == "record_lookup" and rid:
            o = lookup_observation(eid, ts, kv.get("system"), rid, kv.get("record_type"),
                                   kv.get("result"), kv.get("subject_reference"))
            if o:
                out.append(o)
            continue
        if not rid or not system_of(rid):
            continue
        if ev.endswith("_started"):
            continue
        tid = kv.get("trace_id")
        extra = set(trace_keys.get(tid, set())) if tid else set()
        for k in LOOKUP_KEYS:
            if k in kv:
                t = token_for(kv[k])
                if t:
                    extra.add(t)
        fields = {}
        for k, v in kv.items():
            canon = FIELD_ALIASES.get(k)
            if canon and k not in ("subject_ref",):
                fields[canon] = None if is_null(v) else v
        if "subject_ref" in kv:
            fields["ref"] = None if is_null(kv["subject_ref"]) else kv["subject_ref"]
        flags = {}
        category = None
        present = _present_from_kv(kv)
        if "enabled" in kv:
            flags["enabled"] = _bool(kv["enabled"])
        if "restore_allowed" in kv:
            flags["restore_allowed"] = _bool(kv["restore_allowed"])
        if ev == "restore_authorization_completed":
            flags["restore_allowed"] = kv.get("decision", "").lower() == "allow"
        if ev == "restore_candidate_evaluated":
            elig = _bool(kv.get("eligible"))
            block = _bool(kv.get("deletion_block"))
            flags["restore_allowed"] = bool(elig) and not bool(block)
        if "available" in kv:
            flags["available"] = _bool(kv["available"])
            if flags["available"] is False:
                present = False
        if "archive_present" in kv and _bool(kv["archive_present"]) is False:
            present = False
        if "direct_identifiers" in kv:
            flags["identifiable"] = kv["direct_identifiers"] not in ("0", "false")
        if ev in ("message_pii_scan", "attachment_pii_scan", "analytics_identity_scan"):
            flags["identifiable"] = True
            mv = token_for(kv.get("matched_value"))
            if mv:
                kind, val = mv.split(":", 1)
                fields[{"email": "email", "phone": "phone", "hash": "email_hash"}.get(kind, "ref")] = kv["matched_value"]
        if ev == "attachment_pii_scan" or "file" in kv and rid.startswith("support"):
            category = "SUPPORT_ATTACHMENT"
        if ev == "message_read":
            txt = kv.get("message_text", "")
            toks = tokens_in_text(txt)
            flags["identifiable"] = bool({t for t in toks if not t.startswith("user:")})
            flags["redacted"] = not flags["identifiable"]
        if ev == "contact_lookup_completed":
            # a marketing-contact lookup keyed by a hashed e-mail: a secondary identifier
            category = "SECONDARY_IDENTIFIER"
            flags["identifiable"] = True
        if ev == "deletion_marker_check":
            flags["deletion_marker"] = _bool(kv.get("marker_found"))
        if ev == "retained_order_loaded":
            category = "LEGAL_HOLD_RECORD"
        if ev in ("contact_query_completed",):
            # a legacy contact-index entry keyed by the person's e-mail
            category = "SECONDARY_IDENTIFIER"
            flags["identifiable"] = True
        o = _mk(eid, ts, rid, present, fields, extra, flags, category, None, source=f"log {ev}")
        if o:
            out.append(o)
    return out


# ---- hand-over text ---------------------------------------------------------
def parse_text_file(eid, path, captured: datetime):
    out = []
    for line in open(path, encoding="utf-8"):
        parts = [p.strip() for p in line.strip().lstrip("-").split("|")]
        if len(parts) >= 6 and RESOURCE_RE.fullmatch(parts[2] or ""):
            try:
                ts = parse_ts(parts[0])
            except ValueError:
                ts = captured
            subj = parts[5]
            o = lookup_observation(eid, ts, parts[1], parts[2], parts[3], parts[4], subj)
            if o:
                if parts[3] == "SUPPORT_ATTACHMENT":
                    o.category = "SUPPORT_ATTACHMENT"
                out.append(o)
    return out


# ---- PDFs and screenshots -----------------------------------------------------
def _ocr_words(path: str):
    """Words with positions from tesseract (2x upscale, sparse-text mode)."""
    import subprocess
    import tempfile
    try:
        from PIL import Image
        im = Image.open(path).convert("L")
        im = im.resize((im.width * 2, im.height * 2), Image.LANCZOS)
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        im.save(tmp.name)
        src = tmp.name
    except Exception:
        src = path
    out = subprocess.run(["tesseract", src, "-", "--psm", "11", "tsv"], capture_output=True,
                         text=True, timeout=180).stdout
    words = []
    for line in out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 12 or not parts[11].strip():
            continue
        try:
            conf = float(parts[10])
        except ValueError:
            conf = 0
        if conf < 10:
            continue
        x, y, w, h = (int(parts[i]) for i in (6, 7, 8, 9))
        words.append((x, y + h / 2.0, parts[11].strip()))
    return words


def _rows_from_words(words, tol=16):
    rows = []
    for x, yc, w in sorted(words, key=lambda t: (t[1], t[0])):
        for r in rows:
            if abs(r["y"] - yc) <= tol:
                r["words"].append((x, w))
                break
        else:
            rows.append({"y": yc, "words": [(x, w)]})
    out = []
    for r in rows:
        ws = sorted(r["words"])
        out.append({"y": r["y"], "x0": ws[0][0], "x1": ws[-1][0],
                    "text": " ".join(w for _, w in ws), "words": ws})
    return out


def extract_document_rows(path: str, cache_dir: str | None = None):
    """Rows of text with vertical positions (cached).  PDFs: pdftotext lines;
    images: OCR rows."""
    import hashlib
    import subprocess
    key = hashlib.sha1(open(path, "rb").read()).hexdigest()[:16]
    cache = os.path.join(cache_dir, key + ".rows.json") if cache_dir else None
    if cache and os.path.exists(cache):
        return json.load(open(cache, encoding="utf-8"))
    rows = []
    try:
        if path.lower().endswith(".pdf"):
            txt = subprocess.run(["pdftotext", "-layout", path, "-"], capture_output=True,
                                 text=True, timeout=60).stdout
            for i, line in enumerate(txt.splitlines()):
                if line.strip():
                    rows.append({"y": i * 20.0, "x0": len(line) - len(line.lstrip()), "x1": len(line),
                                 "text": " ".join(line.split()), "words": []})
        else:
            rows = _rows_from_words(_ocr_words(path))
            for r in rows:
                r["words"] = [list(w) for w in r["words"]]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        rows = []
    if cache:
        os.makedirs(cache_dir, exist_ok=True)
        json.dump(rows, open(cache, "w", encoding="utf-8"))
    return rows


def extract_document_text(path: str, cache_dir: str | None = None) -> str:
    return "\n".join(r["text"] for r in extract_document_rows(path, cache_dir))


def _fix_ocr(text: str) -> str:
    t = text.replace("\u2014", "-").replace("\u00b7", " ")
    # OCR commonly mangles ids: "data_flow.9846", "account_ 5762", "user 11"
    t = re.sub(r"\b(account|search|analytics|support|export|data[_.]flow|backup|audit[_.]record|tombstone|"
               r"legal[_.]hold|marketing|object|user)[ _.,]+(\d+)\b",
               lambda m: m.group(1).replace(".", "_") + "_" + m.group(2), t)
    t = re.sub(r"(?<=[a-z0-9]),(?=[a-z0-9]+@)", ".", t)        # "g.silva76,jr@" -> "g.silva76.jr@"
    return t


STATUS_WORDS = {
    "enabled": [(r"\b(continuous|healthy|enabled|active|running|live)\b", True),
                (r"\b(disabled|paused|stopped|inactive)\b", False)],
    "restore_allowed": [(r"\b(restore (blocked|disabled|denied)|blocked|legal hold only)\b", False)],
}


def parse_document(eid, path, captured: datetime, cache_dir=None):
    """Business documents and UI screens.  Each resource id on the page is an
    observation (present at capture time).  It is linked to identifiers on the
    same visual row, or - for detail panels - in the block right below it."""
    rows = extract_document_rows(path, cache_dir)
    for r in rows:
        r["text"] = _fix_ocr(r["text"])
    text = "\n".join(r["text"] for r in rows)
    out = []
    is_pdf = path.lower().endswith(".pdf")
    seen = {}
    for i, r in enumerate(rows):
        for m in RESOURCE_RE.finditer(r["text"]):
            rid = m.group(0)
            row_toks = tokens_in_text(r["text"])
            near = set()
            if not ({t for t in row_toks if not t.startswith("user:")}):
                span = 100000.0 if is_pdf else 320.0
                for r2 in rows:
                    if 0 < r2["y"] - r["y"] <= span and (is_pdf or abs(r2["x0"] - r["x0"]) < 700):
                        if RESOURCE_RE.search(r2["text"]) and r2 is not r:
                            break
                        near |= tokens_in_text(r2["text"])
            toks = row_toks | near
            ctx = (r["text"] + " " + " ".join(rr["text"] for rr in rows
                                              if 0 < rr["y"] - r["y"] <= 320)).lower()
            seen.setdefault(rid, [set(), "", r["text"]])
            seen[rid][0] |= toks
            seen[rid][1] += " " + ctx
    for rid, (toks, ctx, rowtext) in seen.items():
        sys_ = system_of(rid)
        flags = {"document": True}
        direct = {t for t in toks if t.split(":")[0] in ("email", "phone", "hash")}
        fields = {}
        for t in direct:
            kind, val = t.split(":", 1)
            fields[{"email": "email", "phone": "phone", "hash": "email_hash"}[kind]] = val
        flags["identifiable"] = bool(direct)
        if sys_ == "integration_service":
            for pat, val in STATUS_WORDS["enabled"]:
                if re.search(pat, ctx):
                    flags["enabled"] = val
                    break
        if sys_ == "backup_service":
            flags["restore_allowed"] = True
            for pat, val in STATUS_WORDS["restore_allowed"]:
                if re.search(pat, ctx):
                    flags["restore_allowed"] = val
        o = _mk(eid, captured, rid, True, fields, toks, flags, None, None,
                source="document " + os.path.basename(path))
        if o:
            if is_pdf and sys_ == "support_platform":
                o.category = "SUPPORT_ATTACHMENT"
            out.append(o)
    return out, text


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------
@dataclass
class Scope:
    """A snapshot that enumerated a whole collection: resources missing from it
    did not exist at that time (for that system)."""
    evidence_id: str
    system: str
    ts: datetime
    table: str
    resource_ids: set


class EvidenceCorpus:
    def __init__(self, dataset_dir: str, cache_dir: str | None = None, verbose=False):
        self.dataset_dir = dataset_dir
        self.cache_dir = cache_dir
        self.observations: list[Observation] = []
        self.scopes: list[Scope] = []
        self.files: dict = {}
        self.doc_text: dict = {}
        self.errors: list = []
        self._load(verbose)
        self.by_resource: dict = {}
        self.by_token: dict = {}
        for o in self.observations:
            self.by_resource.setdefault(o.resource_id, []).append(o)
            for t in o.link_tokens:
                self.by_token.setdefault(t, set()).add(o.resource_id)
        for lst in self.by_resource.values():
            lst.sort(key=lambda o: o.ts)

    def _load(self, verbose):
        manifest = os.path.join(self.dataset_dir, "evidence_files.csv")
        for row in csv.DictReader(open(manifest, encoding="utf-8")):
            fid = row["file_id"]
            path = os.path.join(self.dataset_dir, row["file_path"])
            captured = parse_ts(row["captured_at"])
            self.files[fid] = {"path": path, "captured_at": captured, "origin": row["origin"]}
            if not os.path.exists(path):
                self.errors.append((fid, "missing file"))
                continue
            low = path.lower()
            try:
                if low.endswith(".json"):
                    items = parse_json_file(fid, path, captured)
                elif low.endswith(".sql"):
                    items = parse_sql_file(fid, path, captured)
                elif low.endswith(".log"):
                    items = parse_log_file(fid, path, captured)
                elif low.endswith(".txt"):
                    items = parse_text_file(fid, path, captured)
                elif low.endswith((".pdf", ".png", ".jpg", ".jpeg")):
                    items, text = parse_document(fid, path, captured, self.cache_dir)
                    self.doc_text[fid] = text
                else:
                    items = []
            except Exception as exc:  # keep going: one bad file must not sink the run
                self.errors.append((fid, repr(exc)))
                items = []
            for it in items:
                if isinstance(it, tuple) and it and it[0] == "SCOPE":
                    _, sysname, sts, table, rids = it
                    if sysname:
                        self.scopes.append(Scope(fid, sysname, sts, table,
                                                 {r for r in rids if r}))
                elif it is not None:
                    # an observation can never be later than the file capture
                    if it.ts > captured:
                        it.ts = captured
                    self.observations.append(it)
            if verbose:
                print(fid, len(items))

    # -- queries ------------------------------------------------------------
    def resources_for_tokens(self, tokens: set) -> set:
        out = set()
        for t in tokens:
            out |= self.by_token.get(t, set())
        return out
