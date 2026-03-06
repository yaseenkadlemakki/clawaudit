# ClawAudit — Severity Classification & Scoring

## Check-Level Results

Each individual check returns one of:

| Result | Meaning |
|---|---|
| PASS | Check satisfied, no action needed |
| WARN | Check partially satisfied or best-practice gap |
| FAIL | Check not satisfied, action required |
| UNKNOWN | Cannot be determined from available evidence |

## Severity Mapping

Map FAIL/WARN results to severity based on domain definitions:

| Severity | Description | SLA |
|---|---|---|
| CRITICAL | Immediate exploitation possible; active risk right now | Fix before next session |
| HIGH | Significant security gap; exploitable with low effort | Fix within 1 week |
| MEDIUM | Security best practice gap; elevates risk | Fix within 1 month |
| LOW | Minor hardening gap; defense-in-depth | Fix when convenient |
| INFO | Informational observation; no action required | Note only |

UNKNOWN results are counted as FAIL for scoring purposes (conservative). The distinction between UNKNOWN and FAIL is preserved in the raw evidence appendix so the reader understands which gaps are confirmed deficiencies vs. gaps due to incomplete evidence.

## Domain Score Calculation

```
Domain Score = (PASS count / Total checks in domain) × 100
```

Where UNKNOWN counts as FAIL (0 points). If a domain has 0 checks (e.g., no skills discovered for Domain 2), report that domain as N/A rather than 0% or 100%.

## Overall Compliance Score

```
Overall = (Sum of all PASS across all domains / Total checks across all domains) × 100
```

Only include domains with at least one check in the denominator.

## Severity Weighting Note

The numeric score is unweighted — a deployment with 3 CRITICAL FAILs can still score above 80% overall. **Always read the CRITICAL and HIGH findings list before relying on the overall score.** The score is a completeness indicator, not a safety guarantee.

## Trust Score Calculation (Skills)

| Score | Criteria |
|---|---|
| TRUSTED | SKILL-01 PASS + SKILL-02 PASS/scoped + SKILL-05 PASS + SKILL-09 PASS |
| CAUTION | One of: missing SKILL-01, or SKILL-02 FAIL with low SKILL-05 risk |
| UNTRUSTED | SKILL-02 FAIL + SKILL-05 FAIL, or SKILL-08 FAIL + SKILL-09 FAIL |
| QUARANTINE | SKILL-05 FAIL with active injection patterns, or SKILL-07 calls unknown endpoints |

## Severity → Emoji

- 🔴 CRITICAL
- 🟠 HIGH  
- 🟡 MEDIUM
- 🟢 LOW / INFO
