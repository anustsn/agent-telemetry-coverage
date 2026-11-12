# Pinned sources

`reproduce.sh` downloads these files into `sources/cache/` and checks them there. The cache is ignored by git. None of the source files are redistributed in this repository.

| Source | URL | Pin | SHA-256 of the file used | Licence |
|---|---|---|---|---|
| OWASP Top 10 for Agentic Applications 2026 (PDF, released 9 Dec 2025, 57 pp.) | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ (direct: https://genai.owasp.org/download/52117/?tmstv=1765059207) | file hash | `a2db94cd00b08e0b3a5e5b619afe024bdbcd74503111085705e4f3dd886fcb5c` | CC BY-SA 4.0 |
| OWASP MCP Top 10 2025 (beta) | https://github.com/OWASP/www-project-mcp-top-10 | commit `165fe0f78ef104459237b4a8e0f6e78db9b02391` (29 Jul 2026) | `4f95f31af03f70a136c2f4853d3b85fd781016dc521e94e212a12315492a532b` (GitHub archive) | CC BY-SA 4.0 |
| OpenTelemetry semantic conventions for GenAI | https://github.com/open-telemetry/semantic-conventions-genai | commit `e6658f14c9d9ea0760825f029cb82e7673f48fab` (6 Nov 2026; schema `gen-ai-dev/1.42.0-dev`; no tagged release) | `1ec1c6d759d67dbd6cef6204bfe10c2da4305c26aff253df6632bd323bdc3d5b` (GitHub archive) | Apache-2.0 |
| OpenTelemetry semantic conventions (core) | https://github.com/open-telemetry/semantic-conventions | tag `v1.45.0` (2 Nov 2026) | `32f2ba6b5f38d631174a729b9ddc786dbd54b0e85e19a8889ce974cbe7e2197b` (GitHub archive) | Apache-2.0 |

* The PDF is converted with `pdftotext -layout` (poppler 24.02).
* For the GitHub sources, the commit is the pin. Archive hashes can change if GitHub re-packs an archive. In that case `reproduce.sh` warns and checks that the archive's top folder carries the pinned commit.
