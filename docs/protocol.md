# RQ1 protocol — coverage of agentic-AI monitoring requirements by OpenTelemetry GenAI conventions

**RQ1.** To what extent can the monitoring requirements in the OWASP Top 10 for Agentic Applications (2026) and the
OWASP MCP Top 10 (2025) be evidenced with the OpenTelemetry GenAI semantic conventions?

Status: v0.1, 13 Nov 2026. First coding (coder A) is complete; the independent blind second coding (coder B) is pending.

## 1. Pinned sources (download with `reproduce.sh`; see `sources/SOURCES.md`)
| Source | Version / pin | File | SHA-256 |
|---|---|---|---|
| OWASP Top 10 for Agentic Applications 2026 | PDF released 9 Dec 2025 (internal name "12.6"), 57 pp. | `OWASP_Top10_Agentic_2026.pdf` | a2db94cd00b08e0b3a5e5b619afe024bdbcd74503111085705e4f3dd886fcb5c |
| OWASP MCP Top 10 (2025, beta) | GitHub OWASP/www-project-mcp-top-10 @ 165fe0f (29 Jul 2026) | `owasp_mcp_top10.tar.gz` | 4f95f31af03f70a136c2f4853d3b85fd781016dc521e94e212a12315492a532b |
| OTel GenAI semantic conventions | open-telemetry/semantic-conventions-genai @ e6658f1 (6 Nov 2026); schema gen-ai-dev/1.42.0-dev; no tagged release exists | `otel_genai.tar.gz` | 1ec1c6d759d67dbd6cef6204bfe10c2da4305c26aff253df6632bd323bdc3d5b |
| OTel core semantic conventions | v1.45.0 (2 Nov 2026), the GenAI repo's declared dependency | `otel_core_v1.45.0.tar.gz` | 32f2ba6b5f38d631174a729b9ddc786dbd54b0e85e19a8889ce974cbe7e2197b |

All GenAI, MCP and A2A attributes have stability **development**, so results hold for this pin only.

## 2. Unit of analysis and extraction (`tools/extract_mrs.py`)
* **Unit:** one guidance item (numbered item or top-level bullet; indented sub-bullets join their parent).
  It comes from a prevention, mitigation, detection or remediation section of ASI01–ASI10 or MCP01–MCP10.
* **Candidate:** the item's own text matches the monitoring keyword rule (log, monitor, audit, telemetry, trace,
  record, alert, detect, track, observab*, inspect, baseline, anomal*, provenance, attest, inventor*, SIEM, XDR,
  forensic, visib*, evidence, correlat*, flag), or the item sits in a detection section.
* **Result:** 313 units, 157 candidates (ASI 45 of 86; MCP 112 of 227). The list is in `data/units_extracted.csv`.

## 3. Screening codes (one per candidate)
| Code | Meaning |
|---|---|
| INC | Asks to observe a specific runtime-observable signal. The signals are listed. |
| GEN | Asks for monitoring but names no specific signal. |
| EX-GOV | About the logging system itself: protection, redaction, retention, access, forwarding to SIEM, dashboards, telemetry health. |
| EX-STATIC | Pre-deployment, build-time, periodic audit or active scanning; not runtime telemetry. |
| EX-PREV | Preventive control; the keyword is incidental. |
| EX-RESP | Response, containment or recovery. |
| EX-HEAD | Heading without content. |

Rule: code what the text asks to observe, not what would be useful. The MCP03 "static indicators" are EX-STATIC because
the source itself says they are pre-connection checks.

## 4. Signal catalogue (`data/signals_coded.csv`)
* The 34 signals were derived inductively from the INC units and grouped into 9 layers: identity, correlation,
  goal, tool, supply-chain, content, memory, inter-agent and execution.
* Every signal is used by at least one unit.
* The catalogue is fixed before coder B starts.

## 5. Coverage codes (per signal, against the pinned conventions)
* **C:** a defined attribute, span or event represents the signal at the Required, Conditionally Required or
  Recommended level. This includes core span conventions that standard instrumentation emits, such as HTTP and DB client spans.
* **P:** partial coverage, with one of three types:
  * a = only opt-in content attributes;
  * b = only part of the signal is represented;
  * c = the attribute exists in core, but no GenAI, MCP or A2A span convention uses it.
* **N:** no attribute represents the signal. Inferring it from raw content does not count.

## 6. Aggregation (`tools/rq1_analysis.py`)
Results are reported at three levels:
* signal level (C, P, N);
* mention level (unit × signal);
* requirement level, where the weakest signal decides (all C = fully evidenced; any N = not evidenced).

Results are also given per risk, with a gap list ranked by mentions. The outputs are `results/rq1_summary.md`,
`results/rq1_by_risk.csv` and `results/rq1_signals.csv`.

## 7. Reliability
* Coder B codes a blank copy of `docs/coding_workbook_blank.xlsx` blind; the file has no coder-A codes.
* `tools/rq1_kappa.py` reports Cohen's kappa for three things:
  * screening (7 codes);
  * signal presence, pooled over the units both coders marked INC;
  * coverage (C, P, N).
* Target: κ ≥ 0.70 before consensus. Disagreements are settled in a consensus meeting.
* The final numbers use the consensus codes, and both the pre-consensus κ and the consensus κ are reported.

## 8. Known limitations (to report)
* **Keyword recall.** Two ASI non-candidates look like implicit monitoring requirements: ASI02-M5 (budget ceilings
  imply usage tracking) and ASI06-M2 (scan memory writes). Coder B checks all non-candidate ASI units and reports
  the misses. Recall is reported, and the rule stays fixed.
* **Scope.** Only these two OWASP lists are covered. MITRE ATLAS is used only to label RQ2 scenarios. NIST AI RMF,
  ISO/IEC 42001 and the EU AI Act are out of scope.
* **Unstable conventions.** The OTel GenAI conventions are in development and change weekly. The pin above is the unit of truth.
* **Representability only.** "Covered" means a convention exists. It does not mean any instrumentation library
  emits it. That question belongs to RQ2.
