"""RQ1 step 1: extract candidate monitoring-requirement statements (MRS) from the pinned framework texts.

Unit of analysis: one guidance item (numbered item or bullet) in a prevention / mitigation / detection /
remediation section of OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10) or OWASP MCP Top 10 2025
(MCP01-MCP10). A unit is a candidate when it matches the keyword rule KW (case-insensitive). Candidates are
then screened by hand (include / exclude with a reason code) in the coding workbook.

Usage: python3 -I extract_mrs.py <owasp_agentic_2026.txt> <owasp_mcp_top10/2025 dir> <out.csv>
"""
import csv
import re
import sys
from pathlib import Path

KW = re.compile(r"\blog(s|ging|ged)?\b|monitor|audit|telemetr|\btrac(e|es|ed|ing|eability)\b|record|alert|detect|"
                r"\btrack|observab|inspect|baseline|anomal|provenance|attest|inventor|SIEM|XDR|forensic|visib|"
                r"evidence|correlat|flag", re.I)

ASI_NAMES = {}


def asi_units(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    starts = [i for i, l in enumerate(lines) if re.match(r"^ASI\d\d: ", l) and i > 200]
    end_all = next(i for i, l in enumerate(lines) if i > starts[-1] and re.match(r"^\s*Appendix|^Appendix", l)) \
        if any(re.match(r"^\s*Appendix", l) for l in lines[starts[-1]:]) else len(lines)
    units = []
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else end_all
        sec = lines[s:e]
        rid = lines[s][:5]
        # heading may wrap onto the next line
        name = lines[s][7:].strip()
        if not sec[1].startswith("Description"):
            name += " " + sec[1].strip()
        ASI_NAMES[rid] = name
        try:
            a = next(i for i, l in enumerate(sec) if l.strip().startswith("Prevention and Mitigation"))
        except StopIteration:
            continue
        b = next((i for i, l in enumerate(sec) if i > a and re.match(r"^\s*(Example Attack Scenarios|References)", l)), len(sec))
        body = [l for l in sec[a + 1:b] if not re.search(r"genai\.owasp\.org\s+Page \d+", l)]
        items, cur = [], None
        for l in body:
            m = re.match(r"^\s{0,8}(\d{1,2})\.\s+(.*)", l)
            if m:
                cur = [m.group(1), m.group(2).strip()]
                items.append(cur)
            elif cur and l.strip():
                cur[1] += " " + l.strip()
        for no, text in items:
            text = re.sub(r"\s+", " ", text).replace("- ", "-") if False else re.sub(r"\s+", " ", text)
            units.append({"framework": "OWASP-ASI-2026", "risk_id": rid, "risk_name": name,
                          "section": "Prevention and Mitigation Guidelines", "item_no": no, "text": text})
    return units


def sect_code(t):
    """Short section code used in unit ids: DET(ection), PRE(vention), IMM(ediate remediation), REM(ediation)."""
    t = t.lower()
    if t.startswith("how to detect") or t.startswith("detection"):
        return "DET"
    if t.startswith("how to prevent") or t.startswith("prevention"):
        return "PRE"
    if t.startswith("immediate"):
        return "IMM"
    return "REM"


SECT = re.compile(r"(detect|prevent|mitigation|remediation)", re.I)


def mcp_units(d):
    units = []
    for f in sorted(Path(d).glob("MCP*.md")):
        rid = f.name[:5]
        lines = f.read_text(encoding="utf-8").splitlines()
        title = next((re.sub(r'^title:\s*"?|"$', "", l) for l in lines if l.startswith("title:")), rid)
        # Rules: a numbered line opens a group; plain lines right after it join that group's unit; a top-level
        # bullet is its own unit (prefixed with the group heading); an indented bullet joins the previous unit;
        # outside a group, each plain line is its own unit (e.g. the plain "Detection" lists).
        sec, n, top, buf, in_head = None, 0, None, [], False

        def flush():
            nonlocal buf
            if buf and sec:
                units.append({"framework": "OWASP-MCP-2025", "risk_id": rid, "risk_name": title,
                              "section": sec, "item_no": str(n), "text": re.sub(r"\s+", " ", " ".join(buf)).strip()})
            buf = []

        for l in lines:
            h = re.match(r"^#{2,4}\s+(.*)", l)
            if h:
                flush()
                t = h.group(1).strip()
                sec = t if SECT.search(t) and not re.search(r"scenario|reference|suggestion", t, re.I) else None
                n, top, in_head = 0, None, False
                continue
            if sec is None or not l.strip():
                continue
            num = re.match(r"^\*{0,2}(\d{1,2})\.\s+(.*)", l)
            bul = re.match(r"^(\s*)[-*]\s+(.*)", l)
            if num:
                flush(); n += 1; top = num.group(2).strip().strip("*"); buf = [top]; in_head = True
            elif bul and bul.group(1) == "":
                flush(); n += 1; in_head = False
                t = bul.group(2).strip()
                buf = [(f"[{top}] " if top else "") + t]
            elif bul:                                   # indented bullet: part of the previous unit
                buf.append(("; " if buf else "") + bul.group(2).strip())
            elif in_head or (buf and buf[-1].rstrip().endswith(":")):
                buf.append(l.strip())
            elif not l.startswith("|"):
                flush(); n += 1; buf = [(f"[{top}] " if top else "") + l.strip()]
        flush()
    return units


def main():
    agentic, mcp_dir, out = sys.argv[1:4]
    units = asi_units(agentic) + mcp_units(mcp_dir)
    # drop group headings that only introduce their bullets (the bullets carry the heading as a prefix)
    keep = []
    for i, u in enumerate(units):
        nxt = units[i + 1] if i + 1 < len(units) else None
        if u["framework"] == "OWASP-MCP-2025" and nxt and nxt["text"].startswith(f"[{u['text']}] "):
            continue
        keep.append(u)
    units = keep
    rows = []
    for u in units:
        own = re.sub(r"^\[[^\]]*\] ", "", u["text"])          # keyword rule runs on the item's own text
        hits = sorted({m.group(0).lower() for m in KW.finditer(own)})
        if re.search(r"detect", u["section"], re.I):
            hits.append("<detection-section>")
        u["unit_id"] = f"{u['risk_id']}-{'M' if u['framework'].endswith('ASI-2026') else sect_code(u['section'])}{u['item_no']}"
        u["kw_hits"] = ";".join(hits)
        u["candidate"] = int(bool(hits))
        rows.append(u)
    # unit ids must be unique
    seen = {}
    for r in rows:
        seen[r["unit_id"]] = seen.get(r["unit_id"], 0) + 1
        if seen[r["unit_id"]] > 1:
            r["unit_id"] += f"_{seen[r['unit_id']]}"
    cols = ["unit_id", "framework", "risk_id", "risk_name", "section", "item_no", "candidate", "kw_hits", "text"]
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r[c] for c in cols})
    n = len(rows); c = sum(r["candidate"] for r in rows)
    print(f"units {n}, candidates {c}")
    for fw in ("OWASP-ASI-2026", "OWASP-MCP-2025"):
        sub = [r for r in rows if r["framework"] == fw]
        print(fw, len(sub), "units,", sum(r["candidate"] for r in sub), "candidates")


if __name__ == "__main__":
    main()
