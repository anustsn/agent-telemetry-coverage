#!/usr/bin/env bash
# Rebuild the unit extraction and all result tables from the pinned public sources, then compare them
# with the files committed in data/ and results/.
# Needs: bash, curl, tar, sha256sum, pdftotext (poppler-utils, tested with 24.02) and python3 (standard library only).
set -euo pipefail
cd "$(dirname "$0")"
C=sources/cache
OUT=results/check
mkdir -p "$C" "$OUT"

fetch() {  # <url> <file> <expected sha256> <strict: yes|no>
  # The OWASP site serves an HTML page instead of the PDF to clients without a browser user agent.
  [ -f "$C/$2" ] || curl -fsSL -A 'Mozilla/5.0' -o "$C/$2" "$1"
  got=$(sha256sum "$C/$2" | cut -d' ' -f1)
  if [ "$got" != "$3" ]; then
    if [ "$4" = yes ]; then
      echo "SHA-256 mismatch for $2. If the download failed, get the PDF from" \
           "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ and save it as $C/$2" >&2
      rm -f "$C/$2"; exit 1
    fi
    echo "note: $2 hash differs from the recorded one (GitHub archives may be re-packed); the commit pin is checked instead" >&2
  fi
}

fetch "https://genai.owasp.org/download/52117/?tmstv=1765059207" OWASP_Top10_Agentic_2026.pdf \
  a2db94cd00b08e0b3a5e5b619afe024bdbcd74503111085705e4f3dd886fcb5c yes
fetch https://github.com/OWASP/www-project-mcp-top-10/archive/165fe0f78ef104459237b4a8e0f6e78db9b02391.tar.gz \
  owasp_mcp_top10.tar.gz 4f95f31af03f70a136c2f4853d3b85fd781016dc521e94e212a12315492a532b no
fetch https://github.com/open-telemetry/semantic-conventions-genai/archive/e6658f14c9d9ea0760825f029cb82e7673f48fab.tar.gz \
  otel_genai.tar.gz 1ec1c6d759d67dbd6cef6204bfe10c2da4305c26aff253df6632bd323bdc3d5b no
fetch https://github.com/open-telemetry/semantic-conventions/archive/refs/tags/v1.45.0.tar.gz \
  otel_core.tar.gz 32f2ba6b5f38d631174a729b9ddc786dbd54b0e85e19a8889ce974cbe7e2197b no

pin() {  # <archive> <commit>: the archive's top folder must carry the pinned commit
  top=$(tar tzf "$C/$1" | sed -n 1p)
  [[ $top == *"$2"* ]] || { echo "$1 is not commit $2" >&2; exit 1; }
}
pin owasp_mcp_top10.tar.gz 165fe0f78ef104459237b4a8e0f6e78db9b02391
pin otel_genai.tar.gz e6658f14c9d9ea0760825f029cb82e7673f48fab
for n in owasp_mcp_top10 otel_genai otel_core; do
  rm -rf "${C:?}/$n" && mkdir -p "$C/$n" && tar xzf "$C/$n.tar.gz" -C "$C/$n" --strip-components=1
done
pdftotext -layout "$C/OWASP_Top10_Agentic_2026.pdf" "$C/owasp_agentic_2026.txt"

python3 -I tools/extract_mrs.py "$C/owasp_agentic_2026.txt" "$C/owasp_mcp_top10/2025" "$OUT/units_extracted.csv"
cmp data/units_extracted.csv "$OUT/units_extracted.csv"
python3 -I tools/rq1_analysis.py data/units_extracted.csv data/units_coded.csv data/signals_coded.csv "$OUT/rq1" > /dev/null
for f in rq1_summary.md rq1_by_risk.csv rq1_signals.csv; do cmp "results/$f" "$OUT/$f"; done
echo "OK: extraction and results reproduced from the pinned sources."
echo "OTel registries for coverage checks: $C/otel_genai/model and $C/otel_core/model (see tools/list_attrs.py)."
