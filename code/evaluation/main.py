#!/usr/bin/env python3
"""Evaluation workflow for the deletion-audit agent.

    python3 code/evaluation/main.py            # metrics + writes evaluation_report.md

1. Sample set   - dataset/sample_deletion_requests.csv vs dataset/sample_output.csv
2. Custom cases - six hand-built scenarios (custom_cases.py), run end to end
3. Ablation     - the same sample set with individual ideas switched off, to show
                  what each improvement is worth
4. Hidden-set sanity checks - format/consistency checks on output.csv (no labels)

Metrics
  status accuracy   deletion_status exact match per case
  step P/R/F1       a step matches when (phase, system_id, resource_id, operation,
                    state, evidence_id) all match; step_no is ignored
  field accuracy    gold steps aligned to predicted steps on (phase, resource_id);
                    each of the other fields is scored separately
  sequence accuracy the whole steps_json array is identical (order included)
"""
from __future__ import annotations

import csv
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = os.path.dirname(HERE)
REPO = os.path.dirname(CODE)
sys.path.insert(0, CODE)
sys.path.insert(0, HERE)

from ghost_audit.audit import DeletionAuditAgent  # noqa: E402
import custom_cases  # noqa: E402

FIELDS = ["system_id", "operation", "state", "evidence_id"]


def step_key(s):
    return (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"], s["evidence_id"])


def score(pred: dict, gold: dict):
    """pred/gold: case_id -> (status, steps)."""
    m = Counter()
    per_case = {}
    for cid, (gst, gsteps) in gold.items():
        pst, psteps = pred.get(cid, ("MISSING", []))
        m["cases"] += 1
        m["status_ok"] += pst == gst
        gk = Counter(step_key(s) for s in gsteps)
        pk = Counter(step_key(s) for s in psteps)
        tp = sum((gk & pk).values())
        m["tp"] += tp
        m["gold_steps"] += sum(gk.values())
        m["pred_steps"] += sum(pk.values())
        seq_ok = [step_key(s) for s in gsteps] == [step_key(s) for s in psteps] and \
            [s["step_no"] for s in psteps] == list(range(1, len(psteps) + 1))
        m["seq_ok"] += seq_ok
        # field-level: align on (phase, resource_id)
        pidx = {(s["phase"], s["resource_id"]): s for s in psteps}
        for g in gsteps:
            p = pidx.get((g["phase"], g["resource_id"]))
            m["aligned_total"] += 1
            if p:
                m["aligned_found"] += 1
            for f in FIELDS:
                m[f"field_{f}"] += bool(p) and p[f] == g[f]
        per_case[cid] = {"status_ok": pst == gst, "seq_ok": seq_ok, "pred_status": pst, "gold_status": gst,
                         "missing": [step_key(s) for s in gsteps if step_key(s) not in pk],
                         "extra": [step_key(s) for s in psteps if step_key(s) not in gk]}
    prec = m["tp"] / m["pred_steps"] if m["pred_steps"] else 1.0
    rec = m["tp"] / m["gold_steps"] if m["gold_steps"] else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    out = {
        "cases": m["cases"],
        "status_accuracy": m["status_ok"] / m["cases"],
        "step_precision": prec, "step_recall": rec, "step_f1": f1,
        "sequence_accuracy": m["seq_ok"] / m["cases"],
        "resource_coverage": m["aligned_found"] / max(m["aligned_total"], 1),
    }
    for f in FIELDS:
        out[f"field_{f}_accuracy"] = m[f"field_{f}"] / max(m["aligned_total"], 1)
    return out, per_case


def run_agent(dataset_dir, requests_csv, extra_known=(), features=None, cache=None):
    reqs = list(csv.DictReader(open(requests_csv, encoding="utf-8")))
    known = list(reqs)
    for p in extra_known:
        if os.path.exists(p):
            known += list(csv.DictReader(open(p, encoding="utf-8")))
    agent = DeletionAuditAgent(dataset_dir, cache_dir=cache, use_llm=False, features=features)
    agent.prepare(known)
    return {r["case_id"]: (res.status, res.steps) for r in reqs for res in [agent.audit(r)]}, agent


def load_gold(path):
    return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"]))
            for r in csv.DictReader(open(path, encoding="utf-8"))}


def fmt(x):
    return f"{100 * x:.1f}%"


def metrics_table(rows):
    keys = ["status_accuracy", "step_precision", "step_recall", "step_f1", "sequence_accuracy",
            "resource_coverage"] + [f"field_{f}_accuracy" for f in FIELDS]
    lines = ["| metric | " + " | ".join(name for name, _ in rows) + " |",
             "|---|" + "---|" * len(rows)]
    for k in keys:
        lines.append(f"| {k} | " + " | ".join(fmt(m[k]) for _, m in rows) + " |")
    return "\n".join(lines)


def hidden_checks(path):
    if not os.path.exists(path):
        return ["output.csv not found - run code/main.py first"], {}
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    issues = []
    stats = Counter()
    req_ids = [r["case_id"] for r in csv.DictReader(open(os.path.join(REPO, "dataset", "deletion_requests.csv")))]
    if [r["case_id"] for r in rows] != req_ids:
        issues.append("row order / ids differ from deletion_requests.csv")
    for r in rows:
        steps = json.loads(r["steps_json"])
        stats[r["deletion_status"]] += 1
        stats["steps"] += len(steps)
        if r["deletion_status"] == "COMPLETE":
            evs = {s["evidence_id"] for s in steps}
            stats["complete_single_evidence_file"] += len(evs) == 1
            stats["complete_with_account_check"] += any(s["system_id"] == "account_service" for s in steps)
        if r["deletion_status"] == "INCOMPLETE":
            stats["incomplete_with_account_check"] += any(
                s["system_id"] == "account_service" and s["phase"] == "VERIFICATION" for s in steps)
        phases = [s["phase"] for s in steps]
        if phases != sorted(phases, key=["FINDING", "REMEDIATION", "VERIFICATION"].index):
            issues.append(f"{r['case_id']}: phase order")
    stats["rows"] = len(rows)
    return issues, dict(stats)


def main():
    cache = os.path.join(CODE, "extracted_text")
    ds = os.path.join(REPO, "dataset")
    gold = load_gold(os.path.join(ds, "sample_output.csv"))
    sample_csv = os.path.join(ds, "sample_deletion_requests.csv")
    main_csv = os.path.join(ds, "deletion_requests.csv")

    # 1. sample set (full system)
    pred, agent = run_agent(ds, sample_csv, [main_csv], cache=cache)
    full, per_case = score(pred, gold)

    # 3. ablations
    ablations = [("full system", full)]
    for off in ["worker_queue_accounts", "anonymized_attribution", "request_window", "snapshot_coverage"]:
        feats = set(DeletionAuditAgent.ALL_FEATURES) - {off}
        p2, _ = run_agent(ds, sample_csv, [main_csv], features=feats, cache=cache)
        ablations.append((f"without {off}", score(p2, gold)[0]))
    base_feats = set()
    p3, _ = run_agent(ds, sample_csv, [main_csv], features=base_feats, cache=cache)
    ablations.append(("evidence-only baseline", score(p3, gold)[0]))

    # 2. custom cases
    cdir = os.path.join(HERE, ".custom_dataset")
    expected = custom_cases.build(cdir)
    cpred, _ = run_agent(cdir, os.path.join(cdir, "deletion_requests.csv"), cache=cache)
    cm, cper = score(cpred, expected)

    # 4. hidden-set checks
    issues, stats = hidden_checks(os.path.join(REPO, "output.csv"))

    print("SAMPLE SET")
    for k, v in full.items():
        print(f"  {k:28s} {v if isinstance(v, int) else fmt(v)}")
    print("CUSTOM CASES")
    for cid, info in cper.items():
        print(f"  {cid}: status {'OK' if info['status_ok'] else 'FAIL'}  sequence {'OK' if info['seq_ok'] else 'FAIL'}")
        for x in info["missing"]:
            print("     missing", x)
        for x in info["extra"]:
            print("     extra  ", x)
    print("ABLATION (sample set)")
    print(metrics_table(ablations))
    print("HIDDEN SET CHECKS", stats, issues[:5])

    write_report(full, per_case, cm, cper, ablations, stats, issues, agent)
    return 0


def write_report(full, per_case, cm, cper, ablations, stats, issues, agent):
    failing = {c: i for c, i in per_case.items() if not i["seq_ok"]}
    lines = []
    A = lines.append
    A("# Evaluation report - Ghost Data Still Exists\n")
    A("Generated by `python3 code/evaluation/main.py` (deterministic; no LLM calls are needed for these numbers).\n")
    A("## 1. Sample set (32 cases with published answers)\n")
    A(f"- **Case-level status accuracy:** {fmt(full['status_accuracy'])} ({round(full['status_accuracy'] * full['cases'])}/{full['cases']})")
    A(f"- **Step-level:** precision {fmt(full['step_precision'])}, recall {fmt(full['step_recall'])}, F1 {fmt(full['step_f1'])}"
      " (a step must match phase, system, resource, operation, state and evidence id)")
    A("- **Field-level** (gold steps aligned to predicted steps on phase + resource):  " + ", ".join(
        f"{f} {fmt(full[f'field_{f}_accuracy'])}" for f in FIELDS) + f"; resource coverage {fmt(full['resource_coverage'])}")
    A(f"- **Sequence accuracy** (entire `steps_json` array identical, order included): {fmt(full['sequence_accuracy'])}"
      f" ({round(full['sequence_accuracy'] * full['cases'])}/{full['cases']})\n")
    A("### Remaining sample mismatches\n")
    A("| case | gold status | predicted | missing steps | extra steps | why |")
    A("|---|---|---|---|---|---|")
    reasons = {
        "case_18": "gold verifies audit_record_6645, which appears in no evidence file and no activity row",
        "case_20": "gold verifies audit_record_5569, which appears in no evidence file and no activity row",
        "case_04": "gold cites account_004, which appears in no evidence file and no activity row",
    }
    for cid, info in failing.items():
        A(f"| {cid} | {info['gold_status']} | {info['pred_status']} | "
          + "<br>".join(f"{x[3]} {x[2]}" for x in info["missing"]) + " | "
          + "<br>".join(f"{x[3]} {x[2]}" for x in info["extra"]) + f" | {reasons.get(cid, 'see trace')} |")
    A("\nThese identifiers cannot be derived from any participant-visible file, so we treat them as an upper bound"
      " rather than tuning towards them.\n")
    A("## 2. Custom evaluation cases (built by us)\n")
    A("Each case is a tiny synthetic dataset written by `code/evaluation/custom_cases.py` and run through the"
      " real agent end to end (same file formats as `dataset/`).\n")
    A("| case | scenario | what it tests | expected | result |")
    A("|---|---|---|---|---|")
    desc = {
        "ccase_01": ("export request: \"send me a copy... don't delete anything\"", "intent gate: negated deletion words", "NOT_APPLICABLE, []"),
        "ccase_02": ("profile gone from the primary table but alive on the failover replica", "replication drift inside one SQL capture", "INCOMPLETE: report + delete account, verify audit record retained"),
        "ccase_03": ("snapshot proves deletion; a look-alike `.jr` e-mail hit and a log captured after `audit_at`", "decoy identifiers and the audit cut-off", "COMPLETE, only evidence captured before audit_at cited"),
        "ccase_04": ("request uses an old e-mail; the tombstone still holds name + new e-mail", "historical identity + ACCOUNT_TOMBSTONE redaction rule", "INCOMPLETE: REPORT_EXPOSED_PII + REDACT tombstone"),
        "ccase_05": ("audit log, legal hold, redacted ticket, disabled flow, blocked backup", "RETAIN rules and verify-only answers, evidence per check", "COMPLETE with 5 cited verifications"),
        "ccase_06": ("connector still enabled, backup still restorable", "recreation paths + remediation order (disable/block before anything else)", "INCOMPLETE: DISABLE, BLOCK, then verify"),
    }
    for cid, info in cper.items():
        d = desc.get(cid, ("", "", ""))
        A(f"| {cid} | {d[0]} | {d[1]} | {d[2]} | {'PASS' if info['seq_ok'] and info['status_ok'] else 'FAIL'} |")
    A(f"\nCustom-case metrics: status accuracy {fmt(cm['status_accuracy'])}, step F1 {fmt(cm['step_f1'])},"
      f" sequence accuracy {fmt(cm['sequence_accuracy'])}.\n")
    A("## 3. Ablation - what each idea is worth (sample set)\n")
    A(metrics_table(ablations) + "\n")
    A("- *worker_queue_accounts*: many requests never show their account id next to an identifier; the id only"
      " exists in the deletion worker's queue. Without joint attribution those cases lose their account check.")
    A("- *anonymized_attribution*: an anonymised analytics profile has no identifier left by definition; it is"
      " tied to its request through the worker's learned schedule phase.")
    A("- *request_window*: observations from long before the request (a previous deletion of the same user) must"
      " not decide today's state.")
    A("- *snapshot_coverage*: an empty account snapshot only proves absence for people that snapshot covers.\n")
    A("## 4. Failures found and improvements made\n")
    A("| # | failure observed | fix |")
    A("|---|---|---|")
    fixes = [
        ("First pass linked every id on an OCR'd screenshot to every e-mail on it (a connector console showed two customers' flows).",
         "Row-aware OCR: tesseract TSV on a 2x upscale, words grouped into visual rows; ids link to identifiers on their own row or the detail panel under them."),
        ("`reported_status` and worker `SUCCESS` were trusted in early drafts.", "Status comes only from observed state at `audit_at`; activity rows are used for linking, never as proof."),
        ("Files captured after `audit_at` leaked into answers (e.g. a log exported two days later).", "Evidence filter on manifest `captured_at <= audit_at`; observations can never be later than their file."),
        ("An empty account snapshot was read as 'every account is gone', flipping a still-present account to ABSENT.", "Snapshot absence only counts when the snapshot covers the person (holds another of their records), or nothing else was ever seen for that record."),
        ("Whole-database SQL captures with no account rows gave no absence proof, so COMPLETE cases cited two different files.", "A full capture (primary/replica JSON tables) now scopes every customer system, so the case's own file proves the account is gone."),
        ("A user deleted twice (March and September) got both account ids.", "Observations must fall inside the request window (requested_at - 2 days ... audit_at)."),
        ("Account ids only present in the worker queue were attributed greedily per case, so neighbouring requests stole each other's jobs.", "Joint attribution over all known requests: reported_status <-> job result, learned schedule phase vs. the request's other jobs, and a lead-time prior."),
        ("Phase residues of pre-report and post-report jobs were mixed, making ~30 s-apart accounts indistinguishable.", "Separate calibration for clean-up jobs (fixed minute slots, half-minute tick removed) and retries/checks."),
        ("A legacy contact-index hit (support replica) was treated as a support message to redact.", "Contact-index / marketing contact lookups are SECONDARY_IDENTIFIER -> DELETE, matching rule_02."),
        ("Exports, tombstones and attachments shown only under an alias (statement number, file name, user key) were missed.", "Catalog LINK_RESOURCE_IDENTITY aliases are searched in documents captured just before the catalog run."),
    ]
    for i, (a, b) in enumerate(fixes, 1):
        A(f"| {i} | {a} | {b} |")
    A("\n## 5. Full-dataset sanity checks (no labels available)\n")
    A("| check | value |")
    A("|---|---|")
    for k, v in sorted(stats.items()):
        A(f"| {k} | {v} |")
    A(f"| format issues | {len(issues)} |")
    A(f"\nLearned worker schedule: slot minutes {agent.slot_minutes}, residues {agent.residues}.\n")
    open(os.path.join(HERE, "evaluation_report.md"), "w", encoding="utf-8").write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
