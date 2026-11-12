# Results v0.1 (not yet double-coded; independent second coding pending)

## 1. Screening of candidate units

| framework | candidates | INC | GEN | EX-GOV | EX-STATIC | EX-PREV | EX-RESP | EX-HEAD |
|---|---|---|---|---|---|---|---|---|
| OWASP-ASI-2026 | 45 | 28 | 0 | 0 | 4 | 9 | 4 | 0 |
| OWASP-MCP-2025 | 112 | 50 | 2 | 28 | 23 | 3 | 4 | 2 |
| all | 157 | 78 | 2 | 28 | 27 | 12 | 8 | 2 |

Monitoring requirements kept for coverage analysis: 78 specific (INC) + 2 generic (GEN, no named signal).

## 2. Signal catalogue coverage

34 signals derived from the INC units; every signal is used by at least one unit.

* C (covered by a defined attribute/span): 9
* P (partial): 18 — a: only opt-in content attributes 5; b: only part of the signal 9; c: attribute exists in core but no GenAI/MCP/A2A span uses it 4
* N (not covered): 7

## 3. Signal mentions (unit x signal)

193 mentions: C 68 (35%), P 84 (44%), N 41 (21%)

## 4. Requirement (unit) level — weakest signal decides

* fully evidenced by standard telemetry (all signals C): 8 of 78 (10%)
* partially (weakest = P): 36 (46%)
* not evidenced (at least one N): 34 (44%)

## 5. By risk

| risk | name | INC units | mentions C/P/N | units all-C | units with N |
|---|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | 5 | 3/9/3 | 0 | 3 |
| ASI02 | Tool Misuse and Exploitation | 2 | 6/4/1 | 0 | 1 |
| ASI03 | Identity and Privilege Abuse | 3 | 0/4/5 | 0 | 3 |
| ASI04 | Agentic Supply Chain Vulnerabilities | 1 | 1/2/2 | 0 | 1 |
| ASI05 | Unexpected Code Execution (RCE) | 2 | 0/4/0 | 0 | 0 |
| ASI06 | Memory & Context Poisoning  | 1 | 2/1/0 | 0 | 0 |
| ASI07 | Insecure Inter-Agent Communication | 3 | 4/1/4 | 0 | 3 |
| ASI08 | Cascading Failures | 4 | 8/5/1 | 2 | 1 |
| ASI09 | Human-Agent Trust Exploitation | 4 | 4/5/1 | 0 | 1 |
| ASI10 | Rogue Agents | 3 | 9/1/2 | 1 | 1 |
| MCP01 | MCP01:2025 - Token Mismanagement and Secret Exposure | 3 | 2/2/3 | 0 | 3 |
| MCP02 | MCP02:2025 - Privilege Escalation via Scope Creep | 6 | 3/5/6 | 0 | 5 |
| MCP03 | MCP03:2025 - Tool Poisoning | 3 | 4/1/4 | 0 | 3 |
| MCP04 | MCP04:2025 – Software Supply Chain Attacks & Dependency Tampering | 4 | 1/5/1 | 1 | 1 |
| MCP05 | MCP05:2025 – Command Injection & Execution | 8 | 3/9/0 | 2 | 0 |
| MCP06 | MCP06:2025 – Intent Flow Subversion | 1 | 1/2/1 | 0 | 1 |
| MCP07 | MCP07:2025 – Insufficient Authentication & Authorization | 8 | 1/6/4 | 0 | 4 |
| MCP08 | MCP08:2025 – Lack of Audit and Telemetry | 7 | 12/8/3 | 1 | 3 |
| MCP09 | MCP09:2025 – Shadow MCP Servers | 8 | 2/8/0 | 1 | 0 |
| MCP10 | MCP10:2025 – Context Injection & Over-Sharing | 2 | 2/2/0 | 0 | 0 |

## 6. Gaps (N and P signals, most-mentioned first)

| signal | coverage | mentions | risks |
|---|---|---|---|
| S04 Credential/token use | N | 14 | 6 |
| S17 Tool/schema version and hash | N | 7 | 4 |
| S10 Goal / intent identifier | N | 6 | 5 |
| S02 Verified agent identity | N | 4 | 4 |
| S07 Permission change | N | 4 | 2 |
| S24 Sensitive-data classification | N | 4 | 4 |
| S28 Message integrity / replay check | N | 2 | 1 |
| S01 Agent identifier | P-b | 9 | 6 |
| S13 Policy / guardrail decision | P-c | 9 | 6 |
| S15 Tool arguments | P-a | 7 | 4 |
| S18 MCP server identity and endpoint | P-b | 7 | 1 |
| S20 Configuration change | P-b | 7 | 4 |
| S21 Input content | P-a | 7 | 5 |
| S06 Delegation chain | P-b | 6 | 4 |
| S05 AuthN/AuthZ outcome | P-b | 5 | 2 |
| S30 Process / command execution | P-b | 5 | 3 |
| S12 Human approval / input request | P-b | 4 | 3 |
| S03 Human principal | P-c | 3 | 3 |
| S16 Tool result | P-a | 3 | 2 |
| S19 Component/dependency integrity | P-c | 3 | 2 |
| S22 Output content | P-a | 3 | 3 |
| S26 Content provenance | P-b | 2 | 2 |
| S31 File access | P-c | 2 | 2 |
| S23 System instructions / prompt version | P-a | 1 | 1 |
| S29 Agent discovery / registration | P-b | 1 | 1 |
