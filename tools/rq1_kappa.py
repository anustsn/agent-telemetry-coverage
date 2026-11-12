"""Inter-coder agreement for RQ1 (Cohen's kappa).

Usage: python3 -I rq1_kappa.py <units_coderA.csv> <signals_coderA.csv> <coderB.xlsx>
Reports kappa for (1) screening code, (2) signal presence per unit (pooled over units both coders coded INC),
(3) coverage code C/P/N per signal. Disagreements are listed for the consensus meeting.
"""
import csv
import sys
from collections import Counter

from openpyxl import load_workbook


def kappa(a, b):
    n = len(a)
    if n == 0:
        return float("nan")
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / n / n
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def sheet_rows(ws):
    rows = list(ws.iter_rows(values_only=True))
    head = rows[0]
    return [dict(zip(head, r)) for r in rows[1:] if r[0]]


ua = {r["unit_id"]: r for r in csv.DictReader(open(sys.argv[1], encoding="utf-8"))}
sa = {r["signal_id"]: r for r in csv.DictReader(open(sys.argv[2], encoding="utf-8"))}
wb = load_workbook(sys.argv[3], data_only=True)
ub = {r["unit_id"]: r for r in sheet_rows(wb["screening"])}
sb = {r["signal_id"]: r for r in sheet_rows(wb["signals"])}

done = [k for k in ua if (ub.get(k) or {}).get("screen")]
print(f"units coded by B: {len(done)}/{len(ua)}")
a = [ua[k]["screen"] for k in done]; b = [ub[k]["screen"].strip() for k in done]
print(f"(1) screening kappa = {kappa(a, b):.2f}  (agreement {sum(x == y for x, y in zip(a, b))}/{len(done)})")

both = [k for k in done if ua[k]["screen"] == "INC" and ub[k]["screen"].strip() == "INC"]
pa, pb = [], []
for k in both:
    sa_ = set(x for x in ua[k]["signals"].split(";") if x)
    sb_ = set(x.strip() for x in str(ub[k]["signals"] or "").replace(",", ";").split(";") if x.strip())
    for s in sa:
        pa.append(s in sa_); pb.append(s in sb_)
print(f"(2) signal presence kappa (pooled, {len(both)} units x {len(sa)} signals) = {kappa(pa, pb):.2f}")

sd = [s for s in sa if (sb.get(s) or {}).get("coverage")]
ca = [sa[s]["coverage"] for s in sd]; cb = [str(sb[s]["coverage"]).strip() for s in sd]
print(f"(3) coverage kappa ({len(sd)} signals) = {kappa(ca, cb):.2f}")

print("\nDisagreements for consensus:")
for k in done:
    if ua[k]["screen"] != ub[k]["screen"].strip():
        print(f"  screen {k}: A={ua[k]['screen']} B={ub[k]['screen']}")
for s in sd:
    if sa[s]["coverage"] != str(sb[s]["coverage"]).strip():
        print(f"  coverage {s}: A={sa[s]['coverage']} B={sb[s]['coverage']}")
