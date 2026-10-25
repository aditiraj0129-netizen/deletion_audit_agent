# Token usage and cost - final full-dataset run

Run that produced `output.csv`:

```
python3 code/main.py            # 518 requests, dataset/deletion_requests.csv
```

## Summary

| item | value |
|---|---|
| model providers used | none (deterministic pipeline) |
| model names | - |
| LLM calls | **0** |
| input tokens | 0 |
| output tokens | 0 |
| total tokens | 0 |
| average tokens per request | 0 |
| estimated total cost | **$0.00** |
| estimated cost per request | $0.00 |
| wall-clock time | about 13 s cold (OCR of 11 screenshots + 4 PDFs), about 2 s with the extraction cache |

### Per-model totals

| provider | model | calls | input tokens | output tokens | total tokens | cost |
|---|---|---|---|---|---|---|
| - | - | 0 | 0 | 0 | 0 | $0.00 |
| **overall** | | **0** | **0** | **0** | **0** | **$0.00** |

## Why zero tokens

Every decision in this task can be grounded in the supplied files, so the agent
does the heavy lifting with deterministic components:

| step | component | model cost |
|---|---|---|
| request intent (English, Spanish, Portuguese, French, Japanese, Korean) | multilingual rule set with negation handling (`ghost_audit/intent.py`) | none |
| screenshots | Tesseract OCR (local, 2x upscale, row-aware) | none |
| PDFs | `pdftotext -layout` (local) | none |
| SQL / JSON / 6 log dialects / hand-over text | parsers in `ghost_audit/evidence.py` | none |
| identity, state reconstruction, policy, ordering | `ghost_audit/audit.py`, `policy.py` | none |

The rule-based intent classifier resolves all 518 requests (508 deletion
requests, 10 non-deletion requests). Five of the non-deletion requests fall in
its low-confidence band, but the final run had no API key set, so the rule
answer was used and no LLM was called.

## Optional LLM fallback (off in the final run)

`ghost_audit/intent.py` can ask an LLM to classify a request when the rules are
not confident (deletion words mixed with "don't delete / only / still need"
style constraints, or no deletion verb at all). It is enabled only when the
`ANTHROPIC_API_KEY` environment variable is set (model via `GHOST_AUDIT_MODEL`),
and its usage is counted by `intent.USAGE` and printed at the end of every run.

On this dataset 5 of 518 requests fall in the low-confidence band, so enabling it
would cost about 5 calls x (about 150 input + 40 output tokens) = roughly 1,000
tokens for the whole run, under 2 tokens per request on average. The rules
already give the same answer for those 5 requests, so the fallback adds
robustness for unseen phrasing rather than accuracy here.
