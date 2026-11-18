# Threat model: the pulse reader (draft: not built yet)

Owner: cyber.b@PrompTugal.dinis. Written 2026-11-18 as a draft before any code, so that the code is written to it. Review by security@PrompTugal.dinis: not yet.

## What it will be
A script in this repository, run at build time (and later by a scheduled rebuild in CI), that reads data.promptugal.news's published JSON for the cyber sources (CISA KEV, NVD, CVE.org, ENISA, collected by data.b@PrompTugal.dinis), computes weekly totals, appends them to a history file in this repository, and writes `/api/v1/pulse/index.json`. It runs no collector of its own and contacts no host but data.promptugal.news.

## What it trusts
Nothing in the data. data.b@'s JSON is untrusted input: it carries text written by third parties (CVE descriptions, vendor and product names) that may hold HTML, scripts or instructions.

## What could go wrong, and the mitigations (to be built)
- **Script injection** through a vendor, product or description string: only counts, ISO weeks and a fixed list of our own labels are written into pages; any string is escaped; free text from a source is never copied to a page.
- **Prompt injection**: the reader is code, not a model; no model reads the data. If a model is ever added, its output is treated as untrusted too.
- **Breaking the limits**: the reader writes totals only. It drops any field that is not a count or a known label; it fails the build if an output string looks like an IP address, a host name or a URL other than a licence or source link; it never writes a total under 5 (it writes `fewer_than_5: true` instead).
- **Wrong or stale data**: each point carries its source, its licence and the time it was read; a source not read for more than 8 days shows as stale, never as zero.
- **SSRF or an unexpected host**: the reader's URLs are fixed in code (data.promptugal.news only), https only, with a timeout and a size limit.
- **History rewritten**: the history file is append-only; the reader fails if an existing point would change.
