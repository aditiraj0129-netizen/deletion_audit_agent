# Ghost Data Still Exists - deletion audit agent

An agent that checks whether a person's data is really gone. For every request it
decides `COMPLETE`, `INCOMPLETE` or `NOT_APPLICABLE`, lists what still exposes the
person, and writes the ordered findings -> remediation -> verification plan.

## Setup

Requirements: **Python 3.8+ only.** No pip packages are needed to reproduce `output.csv`.

The text read from the 11 screenshots (OCR) and 4 PDFs is shipped in `code/extracted_text/`
(one JSON file per evidence file, named by the file's SHA-1). The agent reuses it when the
evidence file is unchanged. For a new or changed screenshot/PDF it extracts the text itself,
which needs these optional tools:

```bash
# Debian/Ubuntu
sudo apt-get install -y tesseract-ocr poppler-utils && pip install pillow
# macOS
brew install tesseract poppler && pip install pillow
```

Delete `code/extracted_text/` to force a fresh extraction.

No API key is needed. Optionally set `ANTHROPIC_API_KEY` to let the intent step ask
an LLM about low-confidence requests (see `evaluation/usage_report.md`).

## Run

From the repository root:

```bash
python3 code/main.py                    # -> output.csv (518 rows) + output.trace.jsonl
python3 code/evaluation/main.py         # metrics + rewrites code/evaluation/evaluation_report.md
```

`output.trace.jsonl` explains every answer: the identifiers used, every resource found,
how it was linked (evidence / catalog / worker queue), its state at `audit_at` and the
file that proves it.

## How it works

```
request ──► 1 intent ──► 2 identity ──► 3 discovery ──► 4 attribution ──► 5 state@audit_at ──► 6 policy ──► 7 plan
             rules(+LLM)   user_id +      every evidence    worker-queue       only files captured     deletion_     ordered
             6 languages   old/new        observation that  jobs, solved       <= audit_at; latest     rules.csv     steps_json
                           e-mails,       shares a token    jointly for all    observation wins;
                           phones,        with the person   requests           replicas OR-ed;
                           hashes                                              covering snapshots
                                                                               prove absence
```

| module | job |
|---|---|
| `ghost_audit/evidence.py` | Turns every file into `Observation`s (time, system, resource, present?, identifier fields, flags). Handles SQLite snapshots (primary / regional / reporting / failover replicas), JSON bundles and service exports, six log dialects (logfmt, JSON, syslog, bracketed, pipe, cloud-runtime) with trace-id correlation of `*_started` lookups to `*_completed` results, hand-over text, PDFs (`pdftotext`) and screenshots (row-aware Tesseract OCR). |
| `ghost_audit/identity.py` | Request e-mail (current or historical, any case) -> `user_id` -> every e-mail, phone and e-mail hash from the snapshot and the audit log. |
| `ghost_audit/activity.py` | Reads `system_activity.csv`. Activity rows are claims, so they are never used as proof of state - only for catalog links (`LINK_RESOURCE_IDENTITY`, incl. document aliases), recreation edges (a connector or restore that repopulated a record) and the deletion worker's job schedule. |
| `ghost_audit/audit.py` | Discovery, joint attribution, state reconstruction and planning. |
| `ghost_audit/policy.py` | `deletion_rules.csv` + the output vocabulary and its mandated ordering. |
| `ghost_audit/intent.py` | Deletion-intent gate (negations like "not a request to erase", "marketing lists only", "don't delete"). Optional LLM fallback. |

### Key decisions

* **Claims vs. proof.** `reported_status` and worker results are ignored as evidence. The status is
  derived from what the evidence shows at `audit_at`.
* **Time.** Only files whose manifest `captured_at <= audit_at` are used for state, and only
  observations inside the request window (`requested_at - 2 days ... audit_at`), so a previous
  deletion of the same user does not leak into a new case.
* **Replicas.** At a given capture time a record is present if *any* table (primary or replica)
  holds it - that is how replication drift becomes a finding.
* **Absence.** A full snapshot proves a record is gone only if the snapshot covers that person
  (it contains another of their records); an empty table elsewhere proves nothing.
* **Policy.** delete / redact / anonymize / retain per category; tombstones keep the stable
  `user_id` but must lose name, e-mail, phone and hash; analytics with a `user_id` are still
  attributable; contact-index lookups are secondary identifiers; backups are retained but must
  have restore blocked; enabled connectors are active data flows.
* **Attribution without identifiers.** Many account ids appear only in the deletion worker's
  queue, and anonymised analytics profiles carry no identifier at all. The agent learns the
  worker's scheduling phase from unambiguous requests (`_calibrate_schedule`) and then assigns
  queue jobs to requests jointly (one job, one request), scoring reported-status/job-result
  agreement, phase agreement with the request's other jobs and the usual lead time.
* **Ordering.** Findings, remediation, verification; inside each phase the operation order from
  the problem statement, then `system_id`, then `resource_id`. Disabling flows and blocking
  restores therefore always precede record changes. `COMPLETE` answers contain only
  evidence-backed verifications; `INCOMPLETE` remediation and post-fix checks use `""`.

## Evaluation

`python3 code/evaluation/main.py` reports case, step, field and sequence accuracy on the 32
public samples, runs six custom end-to-end cases, an ablation of each idea, and sanity checks on
`output.csv`. Results are in `evaluation/evaluation_report.md`; token/cost figures in
`evaluation/usage_report.md`.

## Files

```
code/
  main.py                    entry point
  ghost_audit/               the agent (standard library only; Pillow optional for OCR)
  extracted_text/            cached OCR/PDF text for the supplied screenshots and PDFs
  evaluation/main.py         evaluation workflow
  evaluation/custom_cases.py our six extra test cases
  evaluation/evaluation_report.md
  evaluation/usage_report.md
```
