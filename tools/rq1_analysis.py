"""RQ1 analysis: how much of the monitoring guidance in OWASP ASI 2026 + OWASP MCP Top 10 2025 can be evidenced
with the pinned OpenTelemetry GenAI semantic conventions?

Usage: python3 -I rq1_analysis.py <mrs_candidates.csv> <units_coding.csv> <signals_coding.csv> <out_prefix>
Writes <out_prefix>_summary.md, <out_prefix>_by_risk.csv, <out_prefix>_signals.csv
"""
import csv
import sys
from collections import Counter, defaultdict

RANK = {"N": 0, "P": 1, "C": 2}


def load(p):
    return list(csv.DictReader(open(p, encoding="utf-8")))


def main():
    cand_p, units_p, sig_p, out = sys.argv[1:5]
    cand = {r["unit_id"]: r for r in load(cand_p) if r["candidate"] == "1"}
    units = {r["unit_id"]: r for r in load(units_p)}
    sigs = {r["signal_id"]: r for r in load(sig_p)}

    missing = sorted(set(cand) - set(units))
    extra = sorted(set(units) - set(cand))
    assert not missing and not extra, (missing, extra)
    for u in units.values():
        s = [x for x in u["signals"].split(";") if x]
        assert all(x in sigs for x in s), (u["unit_id"], s)
        assert (u["screen"] == "INC") == bool(s), u["unit_id"]
        u["sig"] = s
    used = Counter(x for u in units.values() for x in u["sig"])
    unused = sorted(set(sigs) - set(used))

    lines = ["# Results v0.1 (not yet double-coded; independent second coding pending)", ""]
    # 1. screening
    lines += ["## 1. Screening of candidate units", "", "| framework | candidates | INC | GEN | EX-GOV | EX-STATIC | EX-PREV | EX-RESP | EX-HEAD |",
              "|---|---|---|---|---|---|---|---|---|"]
    codes = ["INC", "GEN", "EX-GOV", "EX-STATIC", "EX-PREV", "EX-RESP", "EX-HEAD"]
    for fw in ("OWASP-ASI-2026", "OWASP-MCP-2025", "all"):
        us = [u for k, u in units.items() if fw == "all" or cand[k]["framework"] == fw]
        c = Counter(u["screen"] for u in us)
        lines.append(f"| {fw} | {len(us)} | " + " | ".join(str(c[x]) for x in codes) + " |")

    inc = [u for u in units.values() if u["screen"] == "INC"]
    gen = [u for u in units.values() if u["screen"] == "GEN"]
    lines += ["", f"Monitoring requirements kept for coverage analysis: {len(inc)} specific (INC) + {len(gen)} generic (GEN, no named signal).", ""]

    # 2. signal catalogue coverage
    cov = Counter(s["coverage"] for s in sigs.values())
    ptype = Counter(s["p_type"] for s in sigs.values() if s["coverage"] == "P")
    lines += ["## 2. Signal catalogue coverage", "",
              f"{len(sigs)} signals derived from the INC units" + (f" (unused: {', '.join(unused)})." if unused else "; every signal is used by at least one unit."), "",
              f"* C (covered by a defined attribute/span): {cov['C']}",
              f"* P (partial): {cov['P']} — a: only opt-in content attributes {ptype['a']}; b: only part of the signal {ptype['b']}; "
              f"c: attribute exists in core but no GenAI/MCP/A2A span uses it {ptype['c']}",
              f"* N (not covered): {cov['N']}", ""]

    # 3. mention-weighted
    m = Counter(sigs[x]["coverage"] for u in inc for x in u["sig"])
    tot = sum(m.values())
    lines += ["## 3. Signal mentions (unit x signal)", "",
              f"{tot} mentions: C {m['C']} ({m['C']/tot:.0%}), P {m['P']} ({m['P']/tot:.0%}), N {m['N']} ({m['N']/tot:.0%})", ""]

    # 4. unit level
    def level(u):
        return min(RANK[sigs[x]["coverage"]] for x in u["sig"])
    lv = Counter(level(u) for u in inc)
    lines += ["## 4. Requirement (unit) level — weakest signal decides", "",
              f"* fully evidenced by standard telemetry (all signals C): {lv[2]} of {len(inc)} ({lv[2]/len(inc):.0%})",
              f"* partially (weakest = P): {lv[1]} ({lv[1]/len(inc):.0%})",
              f"* not evidenced (at least one N): {lv[0]} ({lv[0]/len(inc):.0%})", ""]

    # 5. by risk
    by = defaultdict(list)
    for k, u in units.items():
        by[cand[k]["risk_id"]].append(u)
    rows = []
    lines += ["## 5. By risk", "", "| risk | name | INC units | mentions C/P/N | units all-C | units with N |", "|---|---|---|---|---|---|"]
    for rid in sorted(by, key=lambda r: (r[:3] != "ASI", r)):
        us = [u for u in by[rid] if u["screen"] == "INC"]
        mm = Counter(sigs[x]["coverage"] for u in us for x in u["sig"])
        allc = sum(level(u) == 2 for u in us)
        withn = sum(level(u) == 0 for u in us)
        name = cand[by[rid][0]["unit_id"]]["risk_name"]
        lines.append(f"| {rid} | {name} | {len(us)} | {mm['C']}/{mm['P']}/{mm['N']} | {allc} | {withn} |")
        rows.append({"risk_id": rid, "risk_name": name, "inc_units": len(us), "C": mm["C"], "P": mm["P"], "N": mm["N"],
                     "units_all_C": allc, "units_with_N": withn})
    with open(f"{out}_by_risk.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)

    # 6. gap list
    srows = []
    for sid, s in sigs.items():
        risks = sorted({cand[u["unit_id"]]["risk_id"] for u in inc if sid in u["sig"]})
        srows.append({"signal_id": sid, "signal": s["signal"], "coverage": s["coverage"], "p_type": s["p_type"],
                      "mentions": used[sid], "risks": ";".join(risks), "n_risks": len(risks)})
    srows.sort(key=lambda r: (RANK[r["coverage"]], -r["mentions"]))
    with open(f"{out}_signals.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(srows[0]))
        w.writeheader(); w.writerows(srows)
    lines += ["", "## 6. Gaps (N and P signals, most-mentioned first)", "", "| signal | coverage | mentions | risks |", "|---|---|---|---|"]
    for r in srows:
        if r["coverage"] != "C":
            lines.append(f"| {r['signal_id']} {r['signal']} | {r['coverage']}{('-' + r['p_type']) if r['p_type'] else ''} | {r['mentions']} | {r['n_risks']} |")
    open(f"{out}_summary.md", "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
