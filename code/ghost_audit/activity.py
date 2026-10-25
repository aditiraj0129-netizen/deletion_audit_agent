"""system_activity.csv: operational claims, catalog links and recreation paths.

Activity rows are *claims* (a worker saying "SUCCESS" proves nothing), so they
are never used as proof of state.  They are used for three things:

1. catalog links  - LINK_RESOURCE_IDENTITY rows tie a resource to an e-mail/user;
2. recreation edges - an active connector or a restore job repopulated a record,
   which ties the flow/backup to whoever owns that record;
3. worker scheduling - the deletion worker processes one request as a burst of
   jobs that share a scheduling phase; this lets us attribute records that no
   longer carry any identifier (an anonymised analytics profile) or an account
   id that only appears in the worker queue.
"""
from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass

from .normalize import parse_ts, tokens_in_text
from .evidence import RESOURCE_RE, system_of


@dataclass
class Activity:
    activity_id: str
    ts: object
    event_type: str
    source: str
    target: str
    resource_id: str
    result: str
    details: str


class ActivityLog:
    def __init__(self, dataset_dir: str):
        self.rows: list[Activity] = []
        for r in csv.DictReader(open(os.path.join(dataset_dir, "system_activity.csv"), encoding="utf-8")):
            self.rows.append(Activity(r["activity_id"], parse_ts(r["event_time"]), r["event_type"],
                                      r["source_system"], r["target_system"], r["resource_id"],
                                      r["reported_result"], r["details"]))
        self.rows.sort(key=lambda a: a.ts)
        self.by_resource: dict = {}
        for a in self.rows:
            self.by_resource.setdefault(a.resource_id, []).append(a)
        # 1. catalog links: resource -> tokens
        self.catalog: dict = {}
        self.catalog_flags: dict = {}
        for a in self.rows:
            if a.event_type == "LINK_RESOURCE_IDENTITY":
                toks = tokens_in_text(a.details)
                self.catalog.setdefault(a.resource_id, []).append((a, toks))
                if "belongs only to" in a.details:
                    self.catalog_flags[a.resource_id] = "SOLE_SUBJECT_ATTACHMENT"
        # 2. recreation edges: (flow_or_backup, downstream_resource, activity)
        self.recreations: list = []
        for a in self.rows:
            if a.event_type in ("SYNC_RECORD", "RESTORE_BACKUP") and "repopulated" in a.details:
                m = RESOURCE_RE.search(a.details.split("resource", 1)[-1])
                if m:
                    self.recreations.append((a.resource_id, m.group(0), a))
        # non-deletion classification events
        self.classified_non_deletion = {a.resource_id: a for a in self.rows
                                        if a.event_type == "CLASSIFY_REQUEST"}

    def worker_jobs(self, start, end):
        return [a for a in self.rows if a.source == "deletion_worker" and start <= a.ts <= end]


def phase_affinity(t_anchor, t_job) -> float:
    """How well does `t_job` fit the scheduling phase of the request whose
    account job ran at `t_anchor`?  Jobs for one request are spaced in
    half-minute ticks from a per-request phase, so their second-of-minute
    offsets from the anchor cluster at a few fixed residues.  Returns a score
    in [0, 1]."""
    d = (t_job.second - t_anchor.second) % 60
    best = min(min(abs(d - r), 60 - abs(d - r)) for r in (41.0, 10.5, 52.0, 21.5))
    if best <= 1.0:
        return 1.0
    if best <= 2.0:
        return 0.5
    return 0.0
