#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion audit agent.

Usage (from the repository root):
    python3 code/main.py                       # audits dataset/deletion_requests.csv -> output.csv
    python3 code/main.py --input dataset/sample_deletion_requests.csv --output sample_pred.csv
    python3 code/main.py --no-llm              # never call an LLM (default if no API key)

Every run also writes an explanation trace (one JSON object per case) next to
the output file, so each answer can be inspected: which identifiers were used,
which resources were found, how each was linked and what state it was in.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from ghost_audit import intent as intent_mod  # noqa: E402
from ghost_audit.audit import DeletionAuditAgent  # noqa: E402

REPO = os.path.dirname(HERE)


def natural_key(case_id: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", case_id)]


def read_requests(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_output(path, results):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "deletion_status", "steps_json"])
        for r in sorted(results, key=lambda r: natural_key(r.case_id)):
            w.writerow([r.case_id, r.status, json.dumps(r.steps, ensure_ascii=False, separators=(",", ":"))])


def validate(results, n_expected=None):
    problems = []
    ids = [r.case_id for r in results]
    if len(ids) != len(set(ids)):
        problems.append("duplicate case ids")
    if n_expected is not None and len(ids) != n_expected:
        problems.append(f"expected {n_expected} rows, got {len(ids)}")
    for r in results:
        if r.status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            problems.append(f"{r.case_id}: bad status {r.status}")
        if r.status == "NOT_APPLICABLE" and r.steps:
            problems.append(f"{r.case_id}: NOT_APPLICABLE must have no steps")
        for i, s in enumerate(r.steps, 1):
            if s["step_no"] != i:
                problems.append(f"{r.case_id}: step numbering")
            if r.status == "COMPLETE" and (s["phase"] != "VERIFICATION" or not s["evidence_id"]):
                problems.append(f"{r.case_id}: COMPLETE step without evidence")
            if s["phase"] == "REMEDIATION" and s["evidence_id"]:
                problems.append(f"{r.case_id}: remediation must not cite evidence")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=os.path.join(REPO, "dataset"))
    ap.add_argument("--input", default=None, help="requests CSV (default: dataset/deletion_requests.csv)")
    ap.add_argument("--output", default=os.path.join(REPO, "output.csv"))
    ap.add_argument("--trace", default=None, help="JSONL explanation trace (default: <output>.trace.jsonl)")
    ap.add_argument("--cache", default=os.path.join(HERE, "extracted_text"), help="OCR / text extraction cache")
    ap.add_argument("--no-llm", action="store_true", help="disable the optional LLM fallback")
    args = ap.parse_args(argv)

    t0 = time.time()
    inp = args.input or os.path.join(args.dataset, "deletion_requests.csv")
    requests = read_requests(inp)
    agent = DeletionAuditAgent(args.dataset, cache_dir=args.cache, use_llm=not args.no_llm)
    # Every known request (the audited file plus the sample file) is resolved
    # first, so worker-queue jobs can be attributed jointly and never twice.
    known = list(requests)
    sample = os.path.join(args.dataset, "sample_deletion_requests.csv")
    if os.path.exists(sample) and os.path.abspath(sample) != os.path.abspath(inp):
        known += read_requests(sample)
    main_file = os.path.join(args.dataset, "deletion_requests.csv")
    if os.path.exists(main_file) and os.path.abspath(main_file) != os.path.abspath(inp):
        known += read_requests(main_file)
    agent.prepare(known)

    results = [agent.audit(r) for r in requests]
    write_output(args.output, results)
    trace_path = args.trace or os.path.splitext(args.output)[0] + ".trace.jsonl"
    with open(trace_path, "w", encoding="utf-8") as f:
        for r in sorted(results, key=lambda r: natural_key(r.case_id)):
            f.write(json.dumps({"status": r.status, **r.trace}, default=str) + "\n")

    problems = validate(results, len(requests))
    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    print(f"audited {len(results)} requests in {time.time() - t0:.1f}s -> {args.output}")
    print("status counts:", counts)
    print("evidence files parsed:", len(agent.corpus.files), "| observations:", len(agent.corpus.observations),
          "| parse errors:", len(agent.corpus.errors))
    print("learned worker schedule residues:", agent.residues, "slots:", agent.slot_minutes)
    print("LLM usage:", intent_mod.USAGE.calls or "no LLM calls")
    if problems:
        print("VALIDATION PROBLEMS:", *problems[:20], sep="\n  ")
        return 1
    print("output validated: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
