"""Build the blind coding workbook for coder B (no coder-A codes inside).

Usage: python3 -I make_coderB_workbook.py <mrs_candidates.csv> <signals_coderA.csv> <otel_genai_dir> <otel_core_dir> <out.xlsx>
Only the signal catalogue (id, layer, name, definition) is taken from signals_coderA.csv; its coverage codes are not copied.
"""
import csv
import sys
from pathlib import Path

import yaml
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation

cand_p, sig_p, genai_dir, core_dir, out = sys.argv[1:6]
if Path(out).exists():
    sys.exit(f"{out} exists — refusing to overwrite (coder B may have entered codes)")

cand = [r for r in csv.DictReader(open(cand_p, encoding="utf-8")) if r["candidate"] == "1"]
sigs = list(csv.DictReader(open(sig_p, encoding="utf-8")))

HEAD = Font(bold=True, color="FFFFFF")
HFILL = PatternFill("solid", fgColor="305496")
YELLOW = PatternFill("solid", fgColor="FFF2CC")
WRAP = Alignment(wrap_text=True, vertical="top")

wb = Workbook()
ws = wb.active
ws.title = "README"
readme = [
    "RQ1 coding — coder B (blind). Do not look at any coder-A file before you finish.",
    "",
    "Sources (pinned): OWASP Top 10 for Agentic Applications 2026 (PDF of 9 Dec 2025, sha256 a2db94cd…); "
    "OWASP MCP Top 10 2025 (GitHub commit 165fe0f, 29 Jul 2026); OpenTelemetry semantic-conventions-genai commit e6658f1 "
    "(6 Nov 2026, schema gen-ai-dev/1.42.0-dev) on core semantic-conventions v1.45.0.",
    "",
    "Step 1 — sheet 'screening': for every unit choose one code in column 'screen':",
    "  INC = asks to log/monitor/detect a specific runtime-observable thing; list the signal ids in 'signals' (e.g. S04;S06).",
    "  GEN = asks for monitoring but names no specific signal (e.g. 'monitor behaviour').",
    "  EX-GOV = about the logging system itself: protection, redaction, retention, access to logs, forwarding to SIEM, dashboards, telemetry health.",
    "  EX-STATIC = pre-deployment, build-time, periodic audit or active scanning, not runtime telemetry.",
    "  EX-PREV = preventive control; the monitoring keyword is incidental.",
    "  EX-RESP = response, containment or recovery action.",
    "  EX-HEAD = heading without content.",
    "  Rule: code what the text asks to observe, not what you think would be useful. Use only ids from sheet 'signals'.",
    "",
    "Step 2 — sheet 'signals': for each signal decide coverage in the pinned OpenTelemetry conventions:",
    "  C = a defined attribute/span/event represents the signal and is Required, Conditionally Required or Recommended.",
    "  P = partial; give p_type: a = only opt-in content attributes; b = only part of the signal is represented; "
    "c = attribute exists in core but no GenAI/MCP/A2A span convention uses it.",
    "  N = no attribute represents the signal (inferring it from raw content does not count).",
    "  Write the attribute keys you relied on in 'otel_evidence'. Sheet 'otel_attributes' lists all keys of the pinned registries.",
    "",
    "Yellow cells are the ones to fill. Save and return the file; agreement (Cohen's kappa) is computed by tools/rq1_kappa.py.",
]
for i, t in enumerate(readme, 1):
    ws.cell(i, 1, t).alignment = Alignment(wrap_text=True)
ws.column_dimensions["A"].width = 140


def header(sheet, cols, widths):
    for j, (c, w) in enumerate(zip(cols, widths), 1):
        cell = sheet.cell(1, j, c)
        cell.font, cell.fill = HEAD, HFILL
        sheet.column_dimensions[cell.column_letter].width = w
    sheet.freeze_panes = "A2"


# screening
sc = wb.create_sheet("screening")
cols = ["unit_id", "framework", "risk_id", "risk_name", "section", "text", "screen", "signals", "note"]
header(sc, cols, [13, 15, 7, 28, 22, 90, 11, 22, 30])
dv = DataValidation(type="list", formula1='"INC,GEN,EX-GOV,EX-STATIC,EX-PREV,EX-RESP,EX-HEAD"', allow_blank=True)
sc.add_data_validation(dv)
for i, r in enumerate(cand, 2):
    for j, c in enumerate(cols[:6], 1):
        sc.cell(i, j, r[c]).alignment = WRAP
    for j in (7, 8, 9):
        sc.cell(i, j).fill = YELLOW
    dv.add(f"G{i}")

# signals
sg = wb.create_sheet("signals")
cols = ["signal_id", "layer", "signal", "definition", "coverage", "p_type", "otel_evidence", "note"]
header(sg, cols, [9, 12, 30, 60, 10, 8, 60, 30])
dv1 = DataValidation(type="list", formula1='"C,P,N"', allow_blank=True)
dv2 = DataValidation(type="list", formula1='"a,b,c"', allow_blank=True)
sg.add_data_validation(dv1); sg.add_data_validation(dv2)
for i, r in enumerate(sigs, 2):
    for j, c in enumerate(cols[:4], 1):
        sg.cell(i, j, r[c]).alignment = WRAP
    for j in (5, 6, 7, 8):
        sg.cell(i, j).fill = YELLOW
    dv1.add(f"E{i}"); dv2.add(f"F{i}")

# reference attributes
ref = wb.create_sheet("otel_attributes")
cols = ["key", "registry", "stability", "type", "deprecated", "brief"]
header(ref, cols, [42, 22, 16, 10, 10, 100])
files = sorted(Path(genai_dir, "model").glob("*/registry.yaml"))
core_ns = ["user", "session", "security-rule", "error", "exception", "server", "client", "network", "url", "http", "db",
           "process", "file", "artifact", "tls", "rpc", "jsonrpc"]
files += [p for ns in core_ns for p in [Path(core_dir, "model", ns, "registry.yaml")] if p.exists()]
row = 2
for f in files:
    d = yaml.safe_load(open(f, encoding="utf-8"))
    items = list(d.get("attributes") or [])
    for g in d.get("groups") or []:
        items += [a for a in (g.get("attributes") or []) if "id" in a]
    reg = ("genai/" if genai_dir in str(f) else "core/") + f.parent.name
    for a in items:
        t = a.get("type")
        vals = [a.get("key") or a.get("id"), reg, str(a.get("stability", "")), "enum" if isinstance(t, dict) else str(t),
                "yes" if a.get("deprecated") else "", (a.get("brief") or "").strip().replace("\n", " ")]
        for j, v in enumerate(vals, 1):
            ref.cell(row, j, v)
        row += 1
ref.auto_filter.ref = f"A1:F{row - 1}"
wb.save(out)
print(f"saved {out}: {len(cand)} units, {len(sigs)} signals, {row - 2} reference attributes")
