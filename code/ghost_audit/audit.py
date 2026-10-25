"""The deletion-audit agent: one request in, one (status, steps) answer out.

Pipeline per case
  1. intent      - does the request authorise deletion?            (intent.py)
  2. identity    - user_id + every current/historical identifier   (identity.py)
  3. discovery   - every resource linked to those identifiers in any evidence,
                   catalog link, or recreation path                  (evidence.py / activity.py)
  4. attribution - records that no longer carry an identifier (the account id
                   that only appears in the worker queue, an analytics profile
                   that was already anonymised) are attributed through the
                   deletion worker's job schedule, solved jointly for all
                   requests so one job is never given to two people
  5. state       - what each resource looked like at audit_at, using only
                   evidence captured at or before audit_at
  6. policy      - required treatment per data category            (policy.py)
  7. plan        - findings -> remediation -> verification, ordered
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta

from . import intent as intent_mod
from .activity import ActivityLog
from .evidence import CATEGORY_BY_SYSTEM, EvidenceCorpus, _mk, system_of
from .identity import IdentityResolver
from .normalize import parse_ts, tokens_in_text
from .policy import (ANONYMIZE, DELETE, OP_PHASE, OP_RANK, OP_STATE, REDACT,
                     RETAIN, Policy)

CATEGORY_PRIORITY = ["SUPPORT_ATTACHMENT", "SECONDARY_IDENTIFIER", "ACCOUNT_TOMBSTONE",
                     "LEGAL_HOLD_RECORD", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG"]
# the workflow's reported status mirrors the result its account job reported
STATUS_TO_RESULT = {"COMPLETE": "SUCCESS", "PARTIALLY_COMPLETE": "PARTIAL", "NOT_STARTED": "FAILED"}
LOOKBACK = timedelta(days=2)          # evidence older than the request is about a previous state


@dataclass
class ResourceState:
    resource_id: str
    system: str
    category: str
    status: str                 # PRESENT / ABSENT / UNKNOWN
    identifiable: bool | None = None
    enabled: bool | None = None
    restore_allowed: bool | None = None
    evidence_id: str = ""
    ts: object = None
    how_linked: str = ""


@dataclass
class CaseResult:
    case_id: str
    status: str
    steps: list
    trace: dict = field(default_factory=dict)


@dataclass
class CaseContext:
    req: dict
    ident: object
    linked: dict
    rep: object
    account_job: object = None
    anonymized: list = field(default_factory=list)


class DeletionAuditAgent:
    ALL_FEATURES = frozenset({"worker_queue_accounts", "anonymized_attribution",
                              "schedule_calibration", "request_window", "snapshot_coverage"})

    def __init__(self, dataset_dir: str, cache_dir: str | None = None, use_llm: bool = True,
                 features=None):
        # feature switches exist so the evaluation can measure each idea (ablation)
        self.features = set(self.ALL_FEATURES if features is None else features)
        self.dataset_dir = dataset_dir
        self.corpus = EvidenceCorpus(dataset_dir, cache_dir=cache_dir)
        self.identities = IdentityResolver(dataset_dir)
        self.activity = ActivityLog(dataset_dir)
        self.policy = Policy(dataset_dir)
        self.use_llm = use_llm
        self._add_catalog_links()
        self._token_owner = self._build_token_owners()
        self.contexts: dict = {}
        # second-of-minute offsets (job vs account job) learned by _calibrate_schedule;
        # jobs before the workflow report (clean-up batch) and after it (retries/checks)
        # follow different phases
        self.residues = {"pre": [41.0], "post": [52.0, 21.5]}
        self.slot_minutes, self.tick = [], 29.5

    # ------------------------------------------------------------------ setup
    def _add_catalog_links(self):
        """Catalog rows are identity links, not state.  They also tell us which
        alias (statement number, file name, reference key) a resource is shown
        under in business documents captured just before the catalog run."""
        for rid, items in self.activity.catalog.items():
            for act, toks in items:
                for t in toks:
                    self.corpus.by_token.setdefault(t, set()).add(rid)
                m = re.search(re.escape(rid) + r" \(([^)]+)\)", act.details)
                alias = m.group(1) if m else rid
                norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
                for fid, text in self.corpus.doc_text.items():
                    cap = self.corpus.files[fid]["captured_at"]
                    if not (act.ts - timedelta(minutes=30) <= cap <= act.ts):
                        continue
                    if norm(alias) not in norm(text):
                        continue
                    if any(o.evidence_id == fid for o in self.corpus.by_resource.get(rid, [])):
                        continue
                    doc_toks = tokens_in_text(text)
                    direct = {t for t in doc_toks & toks if not t.startswith("user:")}
                    o = _mk(fid, cap, rid, True, {}, toks,
                            {"document": True, "identifiable": bool(direct)}, None, None,
                            source=f"document alias '{alias}' via {act.activity_id}")
                    if o:
                        if rid.startswith("backup"):
                            o.flags["restore_allowed"] = True
                        self.corpus.observations.append(o)
                        self.corpus.by_resource.setdefault(rid, []).append(o)
                        self.corpus.by_resource[rid].sort(key=lambda x: x.ts)

    def _build_token_owners(self):
        owner = {}
        for uid, row in self.identities.users.items():
            ident = self.identities.resolve(row["email"])
            for t in ident.strong_tokens():
                owner.setdefault(t, set()).add(uid)
        return owner

    def owners_of(self, rid) -> set:
        out = set()
        for o in self.corpus.by_resource.get(rid, []):
            for t in o.link_tokens:
                out |= self._token_owner.get(t, set())
        for act, toks in self.activity.catalog.get(rid, []):
            for t in toks:
                out |= self._token_owner.get(t, set())
        return out

    # ------------------------------------------------------------- discovery
    def discover(self, ident):
        strong = ident.strong_tokens()
        linked = {}
        for rid in self.corpus.resources_for_tokens(strong):
            if not system_of(rid):
                continue
            how = sorted({t.split(":")[0] for o in self.corpus.by_resource.get(rid, [])
                          for t in (o.link_tokens & strong)})
            linked[rid] = "evidence:" + "+".join(how) if how else "catalog"
        for src, dst, act in self.activity.recreations:
            if dst in linked and src not in linked:
                linked[src] = f"recreated {dst} ({act.activity_id})"
        return linked

    # ---------------------------------------------- joint attribution (all cases)
    def prepare(self, requests: list):
        """Resolve every deletion request first, then attribute worker-queue
        jobs jointly so that each job is given to at most one request."""
        for req in requests:
            is_del, why = intent_mod.classify(req["request_text"], use_llm=self.use_llm)
            if not is_del:
                continue
            ident = self.identities.resolve(req["email"], parse_ts(req["audit_at"]))
            linked = self.discover(ident)
            self.contexts[req["case_id"]] = CaseContext(req, ident, linked, parse_ts(req["reported_at"]))
        if "schedule_calibration" in self.features:
            self._calibrate_schedule()
        if "worker_queue_accounts" in self.features:
            self._attribute_accounts()
        else:
            self._account_jobs_from_evidence_only()
        if "anonymized_attribution" in self.features:
            self._attribute_anonymized()

    def _account_jobs_from_evidence_only(self):
        for ctx in self.contexts.values():
            accs = [r for r in ctx.linked if system_of(r) == "account_service"]
            jobs = [a for a in self._case_jobs(ctx, accs) if a.event_type == "DELETE_RECORD"]
            if jobs:
                ctx.account_job = min(jobs, key=lambda a: abs((a.ts - ctx.rep).total_seconds()))

    def _case_jobs(self, ctx, rids):
        lo, hi = ctx.rep - timedelta(hours=3), ctx.rep + timedelta(hours=3)
        return [a for rid in rids for a in self.activity.by_resource.get(rid, [])
                if a.source == "deletion_worker" and lo <= a.ts <= hi]

    def _calibrate_schedule(self):
        """Learn the deletion worker's scheduling pattern from requests whose
        jobs are unambiguous (account + other resources linked by evidence).

        Observed pattern: the clean-up jobs that run *before* the workflow
        report sit in fixed minute slots (one slot per job type) and advance
        by a half-minute tick per slot; the retries/checks *after* the report
        keep a constant second-of-minute phase relative to the account job.
        We learn (a) the slot minutes, (b) the phase of the first slot (pre)
        and (c) the phase peaks of the post-report jobs."""
        TICK = 29.5
        minute_counts = Counter(a.ts.minute for a in self.activity.rows
                                if a.source == "deletion_worker" and a.result == "SUCCESS"
                                and a.event_type in ("ANONYMIZE_RECORD", "REDACT_RECORD", "DISABLE_DATA_FLOW",
                                                     "BLOCK_RESTORE", "RETAIN_RECORD"))
        self.slot_minutes = sorted(m for m, c in minute_counts.items() if c >= 10)
        self.tick = TICK
        hist = {"pre": Counter(), "post": Counter()}
        for ctx in self.contexts.values():
            accs = [r for r in ctx.linked if system_of(r) == "account_service"]
            if len(accs) != 1:
                continue
            acc_jobs = [a for a in self._case_jobs(ctx, accs) if a.event_type == "DELETE_RECORD"]
            if len(acc_jobs) != 1:
                continue
            others = self._case_jobs(ctx, [r for r in ctx.linked if r not in accs])
            for a in others:
                d = self._offset(acc_jobs[0].ts, a.ts, ctx.rep)
                if d is not None:
                    hist["pre" if a.ts < ctx.rep else "post"][int(round(d)) % 60] += 1
        for key, h in hist.items():
            if sum(h.values()) < 8:
                continue
            smooth = {d: h[d] + 0.5 * (h[(d - 1) % 60] + h[(d + 1) % 60]) for d in range(60)}
            peaks = []
            for d in sorted(smooth, key=smooth.get, reverse=True):
                if smooth[d] <= 0 or len(peaks) == 2:
                    break
                if all(min(abs(d - p), 60 - abs(d - p)) > 3 for p in peaks):
                    w = [(k, h[(d + k) % 60]) for k in (-1, 0, 1)]
                    tot = sum(c for _, c in w) or 1
                    peaks.append(round(d + sum(k * c for k, c in w) / tot, 2))
            if peaks:
                self.residues[key] = peaks[:1] if key == "pre" else peaks
        self.schedule_hist = {k: dict(v) for k, v in hist.items()}

    def _offset(self, t_anchor, t_job, rep):
        """Second-of-minute offset of a job relative to its account job.  For
        pre-report jobs the slot's tick advance is removed, so every slot maps
        onto the phase of the first slot."""
        d = (t_job.second - t_anchor.second) % 60
        if t_job < rep and self.slot_minutes:
            k = min(range(len(self.slot_minutes)), key=lambda i: abs(self.slot_minutes[i] - t_job.minute))
            if abs(self.slot_minutes[k] - t_job.minute) > 1:
                return None
            d = (d - self.tick * k) % 60
        return d

    def residue_distance(self, t_anchor, t_job, rep) -> float:
        d = self._offset(t_anchor, t_job, rep)
        if d is None:
            return 99.0
        res = self.residues["pre" if t_job < rep else "post"]
        return min(min(abs(d - r), 60 - abs(d - r)) for r in res)

    def affinity(self, t_anchor, t_job, rep) -> float:
        best = self.residue_distance(t_anchor, t_job, rep)
        return 1.0 if best <= 1.0 else (0.5 if best <= 2.0 else 0.0)

    def _attribute_accounts(self):
        claimed = {r for ctx in self.contexts.values() for r in ctx.linked
                   if system_of(r) == "account_service"}
        pairs = []
        for cid, ctx in self.contexts.items():
            accs = [r for r in ctx.linked if system_of(r) == "account_service"]
            if accs:
                jobs = [a for a in self._case_jobs(ctx, accs) if a.event_type == "DELETE_RECORD"]
                if not jobs:
                    jobs = [a for r in accs for a in self.activity.by_resource.get(r, [])
                            if a.event_type == "DELETE_RECORD"]
                if jobs:
                    ctx.account_job = min(jobs, key=lambda a: abs((a.ts - ctx.rep).total_seconds()))
                continue
            lo, hi = ctx.rep - timedelta(minutes=130), ctx.rep + timedelta(minutes=15)
            anchors = self._case_jobs(ctx, list(ctx.linked))
            want = STATUS_TO_RESULT.get(ctx.req.get("reported_status", ""), "")
            for a in self.activity.rows:
                if not (a.event_type == "DELETE_RECORD" and a.target == "account_service"
                        and lo <= a.ts <= hi):
                    continue
                if a.resource_id in claimed:
                    continue
                owners = self.owners_of(a.resource_id)
                if owners and ctx.ident.user_id not in owners:
                    continue
                score = 4.0 if a.result == want else 0.0
                if anchors:
                    score += 2.0 * sum(self.affinity(a.ts, b.ts, ctx.rep) for b in anchors) / len(anchors)
                # the account job normally runs 40-80 minutes before the workflow reports
                lead = (a.ts - ctx.rep).total_seconds() / 60.0
                score += 1.0 if -80 <= lead <= -40 else (0.5 if -120 <= lead <= 10 else 0.0)
                score += 0.01 * (1.0 - min(abs(lead + 60.0) / 120.0, 1.0))   # deterministic tie-break
                pairs.append((score, cid, a))
        taken_c, taken_r = set(), set()
        for score, cid, a in sorted(pairs, key=lambda p: -p[0]):
            if cid in taken_c or a.resource_id in taken_r:
                continue
            taken_c.add(cid)
            taken_r.add(a.resource_id)
            self.contexts[cid].account_job = a
            self.contexts[cid].linked[a.resource_id] = f"worker queue ({a.activity_id})"

    def _attribute_anonymized(self):
        claimed = {r for ctx in self.contexts.values() for r in ctx.linked}
        pairs = []
        for cid, ctx in self.contexts.items():
            acc = ctx.account_job
            if acc is None:
                # no account job at all: the workflow's own report time is the only anchor
                for a in self.activity.rows:
                    if a.event_type == "ANONYMIZE_RECORD" and a.result != "FAILED" and \
                            ctx.rep - timedelta(minutes=30) <= a.ts <= ctx.rep + timedelta(minutes=10) and \
                            a.resource_id not in claimed and not self.owners_of(a.resource_id):
                        pairs.append((5.0, abs((a.ts - ctx.rep).total_seconds()), cid, a))
                continue
            for a in self.activity.rows:
                if a.event_type != "ANONYMIZE_RECORD" or a.result == "FAILED":
                    continue
                if not (acc.ts <= a.ts <= ctx.rep + timedelta(minutes=30)):
                    continue
                if a.resource_id in claimed or self.owners_of(a.resource_id):
                    continue
                dist = self.residue_distance(acc.ts, a.ts, ctx.rep)
                if dist > 1.5:
                    continue
                pairs.append((dist, abs((a.ts - acc.ts).total_seconds()), cid, a))
        taken_r = set()
        for dist, _, cid, a in sorted(pairs, key=lambda p: (p[0], p[1])):
            if a.resource_id in taken_r:
                continue
            taken_r.add(a.resource_id)
            self.contexts[cid].anonymized.append(a)

    # ------------------------------------------------------------ state at T
    def state_at(self, rid, req, ident_files, allowed) -> ResourceState:
        audit_at = parse_ts(req["audit_at"])
        since = parse_ts(req["requested_at"]) - LOOKBACK
        if "request_window" not in self.features:
            since = parse_ts("2000-01-01T00:00:00Z")
        system = system_of(rid)
        obs_all = self.corpus.by_resource.get(rid, [])
        st = ResourceState(rid, system, self._category(rid, obs_all), "UNKNOWN")
        obs = [o for o in obs_all if allowed(o.evidence_id) and since <= o.ts <= audit_at
               and o.present is not None]
        latest_ts = max((o.ts for o in obs), default=None)
        if latest_ts is not None:
            group = [o for o in obs if o.ts == latest_ts]
            present = any(o.present for o in group)
            st.status = "PRESENT" if present else "ABSENT"
            st.ts = latest_ts
            pres = [o for o in group if o.present] or group
            st.evidence_id = sorted({o.evidence_id for o in pres})[-1]
            idf = [o.has_direct_identifiers() for o in pres]
            if any(v is True for v in idf):
                st.identifiable = True
            elif any(v is False for v in idf):
                st.identifiable = False
            if st.category == "ANALYTICS_PROFILE" and st.identifiable is False and \
                    any(o.has_reference() for o in pres):
                st.identifiable = True              # still attributable through user_id
            for flag in ("enabled", "restore_allowed"):
                vals = [o for o in obs if o.present and o.flags.get(flag) is not None]
                if vals:
                    setattr(st, flag, max(vals, key=lambda o: o.ts).flags[flag])
        # Full snapshots of a system prove absence of what they omit - but only
        # snapshots that cover this person (they hold other records of the same
        # identity), unless nothing at all was ever observed for the record.
        if system == "account_service" or obs:
            groups = {}
            for sc in self.corpus.scopes:
                if sc.system == system and allowed(sc.evidence_id) and since <= sc.ts <= audit_at \
                        and (latest_ts is None or sc.ts > latest_ts):
                    groups.setdefault((sc.evidence_id, sc.ts), []).append(sc)
            absent = [(ts, eid) for (eid, ts), g in groups.items()
                      if all(rid not in sc.resource_ids for sc in g)]
            covering = [x for x in absent if x[1] in ident_files or
                        "snapshot_coverage" not in self.features]
            pick = max(covering) if covering else (max(absent) if absent and not obs_all else None)
            if pick:
                st.status, st.ts, st.evidence_id, st.identifiable = "ABSENT", pick[0], pick[1], None
        return st

    def _category(self, rid, obs):
        cats = {o.category for o in obs}
        if self.activity.catalog_flags.get(rid) == "SOLE_SUBJECT_ATTACHMENT":
            cats.add("SUPPORT_ATTACHMENT")
        for c in CATEGORY_PRIORITY:
            if c in cats:
                return c
        return CATEGORY_BY_SYSTEM.get(system_of(rid), "UNKNOWN")

    # --------------------------------------------------------------- audit
    def audit(self, req) -> CaseResult:
        cid = req["case_id"]
        trace = {"case_id": cid}
        is_del, why = intent_mod.classify(req["request_text"], use_llm=self.use_llm)
        trace["intent"] = why
        if not is_del:
            return CaseResult(cid, "NOT_APPLICABLE", [], trace)
        if cid not in self.contexts:
            self.prepare([req])
        ctx = self.contexts[cid]
        audit_at = parse_ts(req["audit_at"])
        ident = ctx.ident
        trace["user_id"] = ident.user_id
        trace["identity_via"] = ident.matched_via
        trace["identifiers"] = sorted(ident.strong_tokens())

        def allowed(eid):
            f = self.corpus.files.get(eid)
            return f is not None and f["captured_at"] <= audit_at

        tokens = ident.strong_tokens()
        # evidence files that mention this person at all
        ident_files = {o.evidence_id for r in self.corpus.resources_for_tokens(tokens)
                       for o in self.corpus.by_resource.get(r, []) if o.link_tokens & tokens}
        states = {}
        for rid, how in ctx.linked.items():
            st = self.state_at(rid, req, ident_files, allowed)
            st.how_linked = how
            states[rid] = st
        # several account ids: keep the ones that matter for this request
        accs = [s for s in states.values() if s.system == "account_service"]
        if len(accs) > 1:
            known = [s for s in accs if s.status != "UNKNOWN"]
            if ctx.account_job is not None and ctx.account_job.resource_id in states:
                keep = {ctx.account_job.resource_id} | {s.resource_id for s in known}
            else:
                keep = {s.resource_id for s in (known or accs)}
            for s in accs:
                if s.resource_id not in keep:
                    del states[s.resource_id]
        for a in ctx.anonymized:
            st = self.state_at(a.resource_id, req, ident_files, allowed)
            if st.status == "PRESENT" and st.identifiable is False:
                st.how_linked = f"worker schedule ({a.activity_id})"
                states[a.resource_id] = st

        steps, status = self.plan(states)
        trace["resources"] = {rid: {"system": s.system, "category": s.category, "status": s.status,
                                    "identifiable": s.identifiable, "enabled": s.enabled,
                                    "restore_allowed": s.restore_allowed, "evidence": s.evidence_id,
                                    "linked": s.how_linked}
                              for rid, s in sorted(states.items())}
        return CaseResult(cid, status, steps, trace)

    # ----------------------------------------------------------------- plan
    def plan(self, states: dict):
        findings, remediation, verification = [], [], []

        def F(op, s):
            findings.append((op, s.system, s.resource_id, s.evidence_id))

        def R(op, s):
            remediation.append((op, s.system, s.resource_id, ""))

        def V(op, s):
            verification.append((op, s.system, s.resource_id, s.evidence_id))

        for rid, s in states.items():
            action = self.policy.action_for(s.category)
            if s.status == "UNKNOWN":
                # nothing observed in time: we can still state the required end state
                if s.system == "account_service":
                    V("VERIFY_RECORD_ABSENT", s)
                elif action == RETAIN and s.category != "BACKUP_ARCHIVE":
                    V("VERIFY_RECORD_PRESENT", s)
                continue
            if s.system == "integration_service":
                if s.status == "ABSENT":
                    continue
                if s.enabled:
                    F("REPORT_ACTIVE_DATA_FLOW", s)
                    R("DISABLE_DATA_FLOW", s)
                V("VERIFY_DATA_FLOW_DISABLED", s)
                continue
            if s.category == "BACKUP_ARCHIVE":
                if s.status == "ABSENT":
                    continue
                if s.restore_allowed:
                    F("REPORT_RESTORE_RISK", s)
                    R("BLOCK_RESTORE", s)
                V("VERIFY_RESTORE_BLOCKED", s)
                continue
            if action == RETAIN:
                if s.status == "PRESENT":
                    V("VERIFY_RECORD_PRESENT", s)
                continue
            if action == DELETE:
                if s.status == "PRESENT":
                    F("REPORT_REMAINING_RECORD", s)
                    R("DELETE_RECORD", s)
                    V("VERIFY_RECORD_ABSENT", s)
                elif s.system == "account_service":
                    V("VERIFY_RECORD_ABSENT", s)
                continue
            if action in (REDACT, ANONYMIZE):
                if s.status != "PRESENT":
                    continue
                vop = "VERIFY_RECORD_REDACTED" if action == REDACT else "VERIFY_RECORD_ANONYMIZED"
                if s.identifiable:
                    F("REPORT_EXPOSED_PII", s)
                    R("REDACT_RECORD" if action == REDACT else "ANONYMIZE_RECORD", s)
                V(vop, s)
        status = "INCOMPLETE" if findings else "COMPLETE"
        if status == "INCOMPLETE":
            verification = [(op, sy, rid, "") for op, sy, rid, _ in verification]
        else:
            verification = [v for v in verification if v[3]]   # COMPLETE: evidence-backed only
        rows = []
        for items in (findings, remediation, verification):
            items.sort(key=lambda x: (OP_RANK[x[0]], x[1], x[2]))
            rows.extend(items)
        steps = [{"step_no": i, "phase": OP_PHASE[op], "system_id": sy, "resource_id": rid,
                  "operation": op, "state": OP_STATE[op], "evidence_id": ev}
                 for i, (op, sy, rid, ev) in enumerate(rows, 1)]
        return steps, status
