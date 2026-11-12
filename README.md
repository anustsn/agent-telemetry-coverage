# Agent telemetry coverage

**Can standard AI-agent telemetry evidence what OWASP asks organisations to monitor?**

This repository measures how many of the monitoring requirements in the
**OWASP Top 10 for Agentic Applications (2026)** and the **OWASP MCP Top 10 (2025)** can be evidenced with the
**OpenTelemetry (OTel) GenAI semantic conventions**. OTel is the vendor-neutral standard that most agent frameworks
and observability tools use to describe agent, model and tool activity.

Status: **v0.1, 13 Nov 2026.** The coding has not yet been checked by an independent second coder (see [Limitations](#status-and-limitations)).

## Pinned sources
| Source | Pin |
|---|---|
| OWASP Top 10 for Agentic Applications 2026 | PDF released 9 Dec 2025 |
| OWASP MCP Top 10 2025 (beta) | GitHub commit `165fe0f` (29 Jul 2026) |
| OTel GenAI semantic conventions | `semantic-conventions-genai` commit `e6658f1` (6 Nov 2026, schema `gen-ai-dev/1.42.0-dev`) |
| OTel core semantic conventions | v1.45.0 |

URLs, SHA-256 hashes and licences are in [`sources/SOURCES.md`](sources/SOURCES.md). The source files themselves are not in this repository; [`reproduce.sh`](reproduce.sh) downloads and checks them.

## Method
1. **Extract units.** Every guidance item in the prevention, mitigation, detection and remediation sections of ASI01–ASI10 and MCP01–MCP10 is extracted (313 units). An item is a *candidate* if it matches a fixed monitoring keyword rule or sits in a detection section (157 candidates).
2. **Screen.** Each candidate gets one code:
   - `INC`: asks to observe a specific runtime signal;
   - `GEN`: asks for monitoring but names no signal;
   - or an exclusion code: governance of the logging system, static/periodic checks, preventive, response, heading.
3. **Build a signal catalogue.** 34 signals in 9 layers (identity, correlation, goal, tool, supply chain, content, memory, inter-agent, execution) are derived from the INC units.
4. **Code coverage.** Each signal is coded against the pinned conventions:
   - **C**: a defined attribute or span represents it;
   - **P**: partial. Subtypes: a = opt-in content only; b = only part of the signal; c = the attribute exists in core but no GenAI/MCP/A2A span uses it;
   - **N**: no attribute represents it.
5. **Aggregate.** Results are reported per signal, per mention and per requirement. At requirement level the weakest signal decides: all C = fully evidenced; any N = not evidenced.

The full protocol is in [`docs/protocol.md`](docs/protocol.md).

## Results (v0.1)
- **78 specific monitoring requirements** (INC) out of 157 candidates.
- **Signals:** 9 C, 18 P, 7 N out of 34.
- **Mentions:** 193 in total. 35% C, 44% P, 21% N.
- **Requirements:**

| Requirement level | Count | Share |
|---|---|---|
| Fully evidenced (all signals C) | 8 of 78 | **10%** |
| Partially evidenced (weakest signal P) | 36 of 78 | 46% |
| Not evidenced (at least one signal N) | 34 of 78 | **44%** |

**Signals with no OTel representation (N), most-mentioned first**

| Signal | Mentions | Risks |
|---|---|---|
| S04 Credential / token use | 14 | 6 |
| S17 Tool / schema version and hash | 7 | 4 |
| S10 Goal / intent identifier | 6 | 5 |
| S02 Verified agent identity | 4 | 4 |
| S07 Permission change | 4 | 2 |
| S24 Sensitive-data classification | 4 | 4 |
| S28 Message integrity / replay check | 2 | 1 |

**The identity layer is the weakest.** ASI03 (Identity and Privilege Abuse) has 0 C mentions, and MCP02 (scope creep) has 5 of 6 requirements not evidenced.

Full tables, including the per-risk breakdown and the P signals, are in [`results/rq1_summary.md`](results/rq1_summary.md).

## What this means for organisations
- **Agent telemetry records *what* the agent called, not *with which credential* or *on whose verified identity*.**
  - Credential use, verified agent identity and permission changes must come from IAM, gateway and API logs.
  - Linking those logs to agent traces is a design task of its own.
- **Tool arguments, inputs and outputs are only opt-in content attributes** (P-a). Turning them on creates data-protection risk, so plan redaction before enabling them.
- **All GenAI, MCP and A2A attributes are at *development* stability.** Pin the convention version in detection rules and expect changes.

## Status and limitations
- **Not yet double-coded.** An independent blind second coding with Cohen's κ (target ≥ 0.70) is planned for v0.2. The blank workbook ([`docs/coding_workbook_blank.xlsx`](docs/coding_workbook_blank.xlsx)) and [`tools/rq1_kappa.py`](tools/rq1_kappa.py) are ready for it.
- **Representability, not emission.** "Covered" means a convention exists. It does not mean any library emits it.
- **Keyword recall.** Two non-candidate ASI items look like implicit monitoring requirements (ASI02-M5, ASI06-M2).
- **Scope.** Only these two OWASP lists are covered. The results hold for the pinned convention commit only.

## Related work
- **Bánáti et al.**, *Bringing AI and Agentic AI Systems under SOC Supervision* (submitted; supplementary material [doi:10.5281/zenodo.23739618](https://doi.org/10.5281/zenodo.23739618)). It designs a SOC event model on OTel GenAI with added security fields. This repository instead *measures* the gap from the OWASP requirements.
- **Kovrr**, *What OpenTelemetry can and cannot tell you about your AI agents* (Aug 2026). A field test and registry check that finds no approval or consent attributes.
- **OTel** `semantic-conventions-genai` issue #132 proposes threat-detection attributes on agent spans.

## Reproduce
```bash
bash reproduce.sh
```
The script downloads the pinned sources, checks their hashes, re-extracts the units, recomputes all result tables and compares them byte for byte with the committed files.
- **Requirements:** curl, tar, `pdftotext` (poppler-utils) and Python 3.
- **Optional tools:** [`tools/list_attrs.py`](tools/list_attrs.py), [`tools/make_coderB_workbook.py`](tools/make_coderB_workbook.py) and [`tools/rq1_kappa.py`](tools/rq1_kappa.py) also need `openpyxl` and `PyYAML` (see [`requirements.txt`](requirements.txt)).

## Repository layout
```
data/units_extracted.csv     all 313 units with candidate flag and text
data/units_coded.csv         screening code and signal ids for the 157 candidates
data/signals_coded.csv       34-signal catalogue with coverage code and OTel evidence
results/rq1_*                summary, per-risk and per-signal tables
docs/protocol.md             coding protocol
docs/coding_workbook_blank.xlsx   blank workbook for an independent second coder
tools/                       extraction, analysis, workbook and agreement scripts
sources/SOURCES.md           pinned source URLs, hashes and licences
```

## Licence
- **Code** (`tools/`, `reproduce.sh`): MIT, see [`LICENSE`](LICENSE).
- **Data and documents:** CC BY-SA 4.0, because they contain text derived from the OWASP documents. See [`LICENSE-DATA.md`](LICENSE-DATA.md).

## Citation
See [`CITATION.cff`](CITATION.cff).

---

### Монгол хураангуй
OWASP-ийн AI agent болон MCP-ийн Top 10 жагсаалт байгууллагуудаас agent-ийн үйл ажиллагааг хянахыг шаарддаг. Энэ судалгаагаар тэр 78 шаардлагыг OpenTelemetry-ийн GenAI стандарттай нэг бүрчлэн тулгаж үзэв.
- 10% нь стандарт telemetry-гээр бүрэн нотлогдож байна.
- 44% нь огт нотлогдохгүй байна.
- Хамгийн том цоорхой нь credential/token-ийн хэрэглээ болон agent-ийн баталгаажсан identity.
- Эдгээр нотолгоог IAM болон gateway-ийн log-оос авах шаардлагатай.
