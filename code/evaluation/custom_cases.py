"""Hand-built evaluation cases (our own, not from the organisers).

Each case targets one failure mode we worried about.  The builder writes a
tiny, self-contained dataset directory (same file layout as dataset/) so the
real agent runs on it end to end, and returns the expected answers.

  C1 non-deletion      access/export request phrased with "copy"/"don't delete"  -> NOT_APPLICABLE
  C2 replica drift     account deleted on the primary but alive on a failover replica -> INCOMPLETE
  C3 time + decoys     a later-captured log and a look-alike e-mail must both be ignored -> COMPLETE
  C4 history+tombstone request uses an OLD e-mail; tombstone still holds name/e-mail -> INCOMPLETE
  C5 retention         audit log, legal hold, blocked backup, disabled flow, redacted ticket -> COMPLETE
  C6 recreation risk   connector still enabled and backup still restorable -> INCOMPLETE (disable/block first)
"""
from __future__ import annotations

import csv
import json
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))

USERS = [
    # user_id, name, email, phone, email_hash, updated_at
    ("user_9001", "Mira Kovac", "mira.kovac@example.org", "+385 91 555 0101", "a" * 64, "2026-01-01T00:00:00Z"),
    ("user_9002", "Tomas Reyes", "tomas.reyes@example.org", "+34 600 555 102", "b" * 64, "2026-01-01T00:00:00Z"),
    ("user_9003", "Ana Lindqvist", "ana.lindqvist@example.org", "+46 70 555 0103", "c" * 64, "2026-01-01T00:00:00Z"),
    ("user_9004", "Kenji Arai", "kenji.arai.new@example.org", "+81 90 5555 0104", "d" * 64, "2026-01-01T00:00:00Z"),
    ("user_9005", "Lea Moreau", "lea.moreau@example.org", "+33 6 55 55 01 05", "e" * 64, "2026-01-01T00:00:00Z"),
    ("user_9006", "Omar Haddad", "omar.haddad@example.org", "+971 50 555 0106", "f" * 64, "2026-01-01T00:00:00Z"),
]
AUDIT = [("audit_9001", "user_9004", "2026-03-01T10:00:00Z", "email",
          "kenji.arai@example.org", "kenji.arai.new@example.org")]

DEL_TEXT = "Please permanently delete the account associated with this email address."

REQUESTS = [
    # case_id, email, requested_at, reported_status, reported_at, audit_at, text
    ("ccase_01", "mira.kovac@example.org", "2026-06-01T10:00:00Z", "COMPLETE", "2026-06-02T10:00:00Z",
     "2026-06-10T10:00:00Z",
     "Could you send me a copy of everything you hold about me? Please don't delete anything."),
    ("ccase_02", "tomas.reyes@example.org", "2026-06-01T10:00:00Z", "COMPLETE", "2026-06-02T10:00:00Z",
     "2026-06-10T10:00:00Z", DEL_TEXT),
    ("ccase_03", "ana.lindqvist@example.org", "2026-06-01T10:00:00Z", "COMPLETE", "2026-06-02T10:00:00Z",
     "2026-06-10T10:00:00Z", DEL_TEXT),
    ("ccase_04", "kenji.arai@example.org", "2026-06-01T10:00:00Z", "PARTIALLY_COMPLETE", "2026-06-02T10:00:00Z",
     "2026-06-10T10:00:00Z", "I changed my e-mail some time ago. Please erase the account and anything tied to the old address."),
    ("ccase_05", "lea.moreau@example.org", "2026-06-01T10:00:00Z", "COMPLETE", "2026-06-02T10:00:00Z",
     "2026-06-10T10:00:00Z", DEL_TEXT),
    ("ccase_06", "omar.haddad@example.org", "2026-06-01T10:00:00Z", "NOT_STARTED", "2026-06-02T10:00:00Z",
     "2026-06-10T10:00:00Z", DEL_TEXT),
]


def _sql_inventory(ts, rows):
    lines = ["BEGIN TRANSACTION;",
             "CREATE TABLE snapshot_scope (origin_system TEXT PRIMARY KEY, captured_at TEXT NOT NULL);",
             "CREATE TABLE customer_profiles (resource_id TEXT PRIMARY KEY, customer_reference TEXT, full_name TEXT, email TEXT, phone TEXT, email_hash TEXT, account_status TEXT NOT NULL, updated_at TEXT NOT NULL);",
             "CREATE TABLE support_records (resource_id TEXT PRIMARY KEY, customer_reference TEXT, requester_name TEXT, requester_email TEXT, requester_phone TEXT, message_excerpt TEXT NOT NULL, updated_at TEXT NOT NULL);",
             "CREATE TABLE connector_subscriptions (resource_id TEXT PRIMARY KEY, customer_reference TEXT, customer_email TEXT, connector_name TEXT NOT NULL, enabled INTEGER NOT NULL, last_delivery_status TEXT NOT NULL, updated_at TEXT NOT NULL);",
             "CREATE TABLE backup_restore_entries (resource_id TEXT PRIMARY KEY, customer_reference TEXT, customer_email TEXT, archive_key TEXT NOT NULL, restore_allowed INTEGER NOT NULL, updated_at TEXT NOT NULL);",
             "CREATE TABLE security_audit_records (resource_id TEXT PRIMARY KEY, subject_reference TEXT NOT NULL, event_code TEXT NOT NULL, retention_until TEXT NOT NULL, updated_at TEXT NOT NULL);"]
    for sysname in ("account_service", "support_platform", "integration_service", "backup_service", "security_service"):
        lines.append(f"INSERT INTO snapshot_scope VALUES ('{sysname}', '{ts}');")
    lines += rows
    lines.append("COMMIT;")
    return "\n".join(lines) + "\n"


def build(target_dir: str):
    """Write the custom dataset and return {case_id: (status, steps)}."""
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    ev = os.path.join(target_dir, "evidence")
    for sub in ("databases", "records", "logs"):
        os.makedirs(os.path.join(ev, sub))
    shutil.copy(os.path.join(REPO, "dataset", "deletion_rules.csv"), target_dir)

    def wcsv(name, header, rows):
        with open(os.path.join(target_dir, name), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)

    wcsv("user_identities.csv", ["user_id", "name", "email", "phone", "email_hash", "updated_at"], USERS)
    wcsv("user_audit_log.csv", ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"], AUDIT)
    wcsv("deletion_requests.csv", ["case_id", "email", "requested_at", "reported_status", "reported_at",
                                   "audit_at", "request_text"], REQUESTS)
    wcsv("system_activity.csv", ["activity_id", "event_time", "event_type", "source_system", "target_system",
                                 "resource_id", "reported_result", "details"], [])
    manifest = []

    # C2: replica drift - primary empty, failover replica still holds the profile
    open(os.path.join(ev, "databases", "c2_failover.sql"), "w").write(
        "BEGIN TRANSACTION;\n"
        "CREATE TABLE customer_profiles_primary (resource_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, full_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL, account_status TEXT NOT NULL, updated_at TEXT NOT NULL);\n"
        "CREATE TABLE customer_profiles_failover_replica (resource_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, full_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT NOT NULL, account_status TEXT NOT NULL, updated_at TEXT NOT NULL);\n"
        "INSERT INTO customer_profiles_failover_replica VALUES('account_9902','user_9002','Tomas Reyes','tomas.reyes@example.org','+34 600 555 102','ACTIVE','2026-06-05T09:00:00Z');\n"
        "COMMIT;\n")
    manifest.append(("cev_02", "evidence/databases/c2_failover.sql", "test", "2026-06-05T10:00:00Z"))
    open(os.path.join(ev, "logs", "c2_audit.log"), "w").write(
        '2026-06-05T11:00:00Z level=INFO service=security_service trace_id=t-1 event=audit_record_read_completed '
        'resource_id=audit_record_9902 rows=1 subject_reference=user_9002 event_code=ACCOUNT_DELETION_RECORDED\n')
    manifest.append(("cev_02b", "evidence/logs/c2_audit.log", "test", "2026-06-05T11:00:00Z"))

    # C3: snapshot proves the account is gone; a look-alike search hit and a
    #     log captured AFTER audit_at must not change the answer
    bundle3 = {"exported_at": "2026-06-06T12:00:00Z", "snapshots": [
        {"captured_at": "2026-06-06T12:00:00Z", "data_store": "account_service", "collection": "customer_profiles", "records": []},
        {"captured_at": "2026-06-06T12:00:00Z", "data_store": "security_service", "collection": "security_audit_events",
         "records": [{"resource_id": "audit_record_9903", "subject_reference": "user_9003", "event_name": "account_deletion_reviewed"}]},
        {"captured_at": "2026-06-06T12:00:00Z", "data_store": "search_service", "collection": "customer_search_documents",
         "records": [{"resource_id": "search_9931", "index_name": "customer_directory_v3",
                      "document": {"display_name": "Ana Lindqvist", "email": "ana.lindqvist.jr@example.org", "customer_reference": None}}]}]}
    json.dump(bundle3, open(os.path.join(ev, "records", "c3_bundle.json"), "w"), indent=1)
    manifest.append(("cev_03", "evidence/records/c3_bundle.json", "test", "2026-06-06T12:00:00Z"))
    open(os.path.join(ev, "logs", "c3_late.log"), "w").write(
        '2026-06-12T08:00:00Z level=INFO service=search_service trace_id=t-3 resource_id=search_9932 '
        'event=index_query_completed result=hit correlation_key="ana.lindqvist@example.org"\n')
    manifest.append(("cev_03b", "evidence/logs/c3_late.log", "test", "2026-06-12T09:00:00Z"))

    # C4: old e-mail in the request; tombstone still exposes the new e-mail and name
    bundle4 = {"exported_at": "2026-06-06T12:00:00Z", "snapshots": [
        {"captured_at": "2026-06-06T12:00:00Z", "data_store": "account_service", "collection": "customer_profiles", "records": []},
        {"captured_at": "2026-06-06T12:00:00Z", "data_store": "identity_service", "collection": "deleted_customer_references",
         "records": [{"resource_id": "tombstone_9904", "subject_reference": "user_9004", "name": "Kenji Arai",
                      "email": "kenji.arai.new@example.org", "phone": None, "email_hash": None, "account_status": "DELETED"}]},
        {"captured_at": "2026-06-06T12:00:00Z", "data_store": "security_service", "collection": "security_audit_events",
         "records": [{"resource_id": "audit_record_9904", "subject_reference": "user_9004", "event_name": "account_deletion_reviewed"}]}]}
    json.dump(bundle4, open(os.path.join(ev, "records", "c4_bundle.json"), "w"), indent=1)
    manifest.append(("cev_04", "evidence/records/c4_bundle.json", "test", "2026-06-06T12:00:00Z"))
    open(os.path.join(ev, "logs", "c4_lookup.log"), "w").write(
        '2026-06-06T13:00:00Z level=DEBUG service=account_service trace_id=t-4 event=profile_lookup_started lookup_key=kenji.arai@example.org\n'
        '2026-06-06T13:00:01Z level=INFO service=account_service trace_id=t-4 event=profile_lookup_completed resource_id=account_9904 rows=0 http_status=404\n')
    manifest.append(("cev_04b", "evidence/logs/c4_lookup.log", "test", "2026-06-06T13:00:00Z"))

    # C5: everything retained correctly
    rows5 = [
        "INSERT INTO security_audit_records VALUES ('audit_record_9905','user_9005','ACCOUNT_DELETION_RECORDED','2032-12-31T23:59:59Z','2026-06-07T08:00:00Z');",
        "INSERT INTO support_records VALUES ('support_9905','user_9005',NULL,NULL,NULL,'[REDACTED]','2026-06-07T08:00:00Z');",
        "INSERT INTO connector_subscriptions VALUES ('data_flow_9905','user_9005',NULL,'customer_events_connector','0','stopped','2026-06-07T08:00:00Z');",
        "INSERT INTO backup_restore_entries VALUES ('backup_9905','user_9005',NULL,'archive/backup_9905.tar.zst','0','2026-06-07T08:00:00Z');",
    ]
    open(os.path.join(ev, "databases", "c5_inventory.sql"), "w").write(_sql_inventory("2026-06-07T09:00:00Z", rows5))
    manifest.append(("cev_05", "evidence/databases/c5_inventory.sql", "test", "2026-06-07T09:00:00Z"))
    bundle5 = {"exported_at": "2026-06-07T09:30:00Z", "snapshots": [
        {"captured_at": "2026-06-07T09:30:00Z", "data_store": "legal_service", "collection": "retained_order_records",
         "records": [{"resource_id": "legal_hold_9905", "subject_reference": "user_9005", "order_reference": "ORD-1",
                      "retention_reason": "payment_dispute_and_tax_record", "retained_until": "2033-12-31T23:59:59Z"}]}]}
    json.dump(bundle5, open(os.path.join(ev, "records", "c5_legal.json"), "w"), indent=1)
    manifest.append(("cev_05b", "evidence/records/c5_legal.json", "test", "2026-06-07T09:30:00Z"))

    # C6: an enabled connector and a restorable backup
    open(os.path.join(ev, "logs", "c6_ops.log"), "w").write(
        '2026-06-08T08:00:00Z [INFO] [integration_service] [t-61] connector_config_loaded: resource_id="data_flow_9906" enabled="true" scheduler_registered="true" correlation_key="omar.haddad@example.org"\n'
        '2026-06-08T08:01:00Z [DEBUG] [backup_service] [t-62] restore_policy_check_started: subject_key="user_9006"\n'
        '2026-06-08T08:01:02Z [ERROR] [backup_service] [t-62] restore_candidate_evaluated: resource_id="backup_9906" eligible="true" deletion_block="false"\n'
        '2026-06-08T08:02:00Z [INFO] [account_service] [t-63] profile_lookup_completed: resource_id="account_9906" rows="0" http_status="404" correlation_key="omar.haddad@example.org"\n'
        '2026-06-08T08:03:00Z [DEBUG] [security_service] [t-64] audit_record_read_completed: resource_id="audit_record_9906" rows="1" correlation_key="user_9006"\n')
    manifest.append(("cev_06", "evidence/logs/c6_ops.log", "test", "2026-06-08T09:00:00Z"))

    wcsv("evidence_files.csv", ["file_id", "file_path", "origin", "captured_at"], manifest)

    def S(n, phase, sysid, rid, op, state, ev=""):
        return {"step_no": n, "phase": phase, "system_id": sysid, "resource_id": rid,
                "operation": op, "state": state, "evidence_id": ev}
    expected = {
        "ccase_01": ("NOT_APPLICABLE", []),
        "ccase_02": ("INCOMPLETE", [
            S(1, "FINDING", "account_service", "account_9902", "REPORT_REMAINING_RECORD", "PRESENT", "cev_02"),
            S(2, "REMEDIATION", "account_service", "account_9902", "DELETE_RECORD", "ABSENT"),
            S(3, "VERIFICATION", "account_service", "account_9902", "VERIFY_RECORD_ABSENT", "ABSENT"),
            S(4, "VERIFICATION", "security_service", "audit_record_9902", "VERIFY_RECORD_PRESENT", "PRESENT")]),
        "ccase_03": ("COMPLETE", [
            S(1, "VERIFICATION", "security_service", "audit_record_9903", "VERIFY_RECORD_PRESENT", "PRESENT", "cev_03")]),
        "ccase_04": ("INCOMPLETE", [
            S(1, "FINDING", "identity_service", "tombstone_9904", "REPORT_EXPOSED_PII", "PRESENT", "cev_04"),
            S(2, "REMEDIATION", "identity_service", "tombstone_9904", "REDACT_RECORD", "REDACTED"),
            S(3, "VERIFICATION", "account_service", "account_9904", "VERIFY_RECORD_ABSENT", "ABSENT"),
            S(4, "VERIFICATION", "security_service", "audit_record_9904", "VERIFY_RECORD_PRESENT", "PRESENT"),
            S(5, "VERIFICATION", "identity_service", "tombstone_9904", "VERIFY_RECORD_REDACTED", "REDACTED")]),
        "ccase_05": ("COMPLETE", [
            S(1, "VERIFICATION", "legal_service", "legal_hold_9905", "VERIFY_RECORD_PRESENT", "PRESENT", "cev_05b"),
            S(2, "VERIFICATION", "security_service", "audit_record_9905", "VERIFY_RECORD_PRESENT", "PRESENT", "cev_05"),
            S(3, "VERIFICATION", "support_platform", "support_9905", "VERIFY_RECORD_REDACTED", "REDACTED", "cev_05"),
            S(4, "VERIFICATION", "integration_service", "data_flow_9905", "VERIFY_DATA_FLOW_DISABLED", "DISABLED", "cev_05"),
            S(5, "VERIFICATION", "backup_service", "backup_9905", "VERIFY_RESTORE_BLOCKED", "BLOCKED", "cev_05")]),
        "ccase_06": ("INCOMPLETE", [
            S(1, "FINDING", "integration_service", "data_flow_9906", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "cev_06"),
            S(2, "FINDING", "backup_service", "backup_9906", "REPORT_RESTORE_RISK", "ACTIVE", "cev_06"),
            S(3, "REMEDIATION", "integration_service", "data_flow_9906", "DISABLE_DATA_FLOW", "DISABLED"),
            S(4, "REMEDIATION", "backup_service", "backup_9906", "BLOCK_RESTORE", "BLOCKED"),
            S(5, "VERIFICATION", "account_service", "account_9906", "VERIFY_RECORD_ABSENT", "ABSENT"),
            S(6, "VERIFICATION", "security_service", "audit_record_9906", "VERIFY_RECORD_PRESENT", "PRESENT"),
            S(7, "VERIFICATION", "integration_service", "data_flow_9906", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
            S(8, "VERIFICATION", "backup_service", "backup_9906", "VERIFY_RESTORE_BLOCKED", "BLOCKED")]),
    }
    return expected
