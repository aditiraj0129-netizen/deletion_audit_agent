"""Deletion policy: data category -> required treatment, plus the output
vocabulary (operations, states and their mandated ordering)."""
from __future__ import annotations

import csv
import os

# Treatments understood by the planner
DELETE, REDACT, ANONYMIZE, RETAIN, DISABLE, BLOCK = (
    "DELETE", "REDACT", "ANONYMIZE", "RETAIN", "DISABLE", "BLOCK")

# Fallback when deletion_rules.csv does not mention a category
DEFAULT_ACTIONS = {
    "USER_PROFILE": DELETE,
    "SECONDARY_IDENTIFIER": DELETE,
    "SEARCH_INDEX_ENTRY": DELETE,
    "CACHE_ENTRY": DELETE,
    "SUPPORT_MESSAGE": REDACT,
    "SUPPORT_ATTACHMENT": DELETE,
    "ANALYTICS_PROFILE": ANONYMIZE,
    "PRODUCT_TELEMETRY": ANONYMIZE,
    "USER_EXPORT": DELETE,
    "MARKETING_PROFILE": DELETE,
    "EMAIL_DELIVERY_LOG": REDACT,
    "SECURITY_AUDIT_LOG": RETAIN,
    "LEGAL_HOLD_RECORD": RETAIN,
    "BACKUP_ARCHIVE": RETAIN,
    "ACCOUNT_TOMBSTONE": REDACT,
}

# Output vocabulary, in the order mandated by the problem statement
FINDING_OPS = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII",
               "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_OPS = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD",
                   "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFICATION_OPS = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT",
                    "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
                    "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
PHASES = ["FINDING", "REMEDIATION", "VERIFICATION"]
OP_STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
OP_PHASE = {**{o: "FINDING" for o in FINDING_OPS},
            **{o: "REMEDIATION" for o in REMEDIATION_OPS},
            **{o: "VERIFICATION" for o in VERIFICATION_OPS}}
OP_RANK = {o: i for i, o in enumerate(FINDING_OPS + REMEDIATION_OPS + VERIFICATION_OPS)}


class Policy:
    def __init__(self, dataset_dir: str):
        self.rules = {}
        path = os.path.join(dataset_dir, "deletion_rules.csv")
        for r in csv.DictReader(open(path, encoding="utf-8")):
            self.rules[r["data_category"].strip().upper()] = {
                "rule_id": r["rule_id"], "condition": r["condition"],
                "action": r["required_action"].strip().upper()}

    def action_for(self, category: str) -> str:
        if category == "DATA_FLOW":
            return DISABLE
        r = self.rules.get(category)
        if r:
            return r["action"]
        return DEFAULT_ACTIONS.get(category, DELETE)

    def rule_id(self, category: str) -> str:
        r = self.rules.get(category)
        return r["rule_id"] if r else ""
