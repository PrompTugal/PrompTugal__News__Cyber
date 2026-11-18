# Threat model: the pulse reader

Owner: cyber.b@PrompTugal.dinis. Written 2026-11-18 as a draft; updated the same day when the reader was built (`scripts/pulse-read.mjs`). Review by security@PrompTugal.dinis: not yet.

## What it is
A Node script (built-ins only), run by the site lead before a release; not run by CI and not on a schedule yet. It fetches two fixed URLs, https only, on data.promptugal.news (`/api/v1/cisa-kev/latest.json`, `/api/v1/nvd-cve/latest.json`, published by data.b@PrompTugal.dinis), counts, and writes `src/api/v1/pulse/index.json` and two append-only history files in `src/api/v1/pulse/history/`. It runs no collector of its own and contacts no other host. No model reads the data.

## What it trusts
Nothing in the data. The files carry third-party text (vendor, product and CNA names, descriptions) that may hold HTML, scripts or instructions.

## What could go wrong, and the mitigations (built)
- **Script injection or copied text**: the reader builds its output from integers, ISO dates and times, and our own fixed labels only; no feed object or string is copied. The page builder escapes every value and allows only https links.
- **Unexpected shapes**: dates must match ISO formats, counts must be whole numbers in range, NVD severity bands must be exactly the six known ones and add up to the total; otherwise the reader stops.
- **Breaking the limits**: before writing, every output string is checked; anything that looks like an IP address or a host name (other than our own fixed source URLs and licence links) stops the reader. Until 18 November 2026, about 23:40 UTC, totals under 5 were hidden; Dinis dropped that floor, since these totals count catalogue entries, not organisations.
- **History rewritten**: a completed week that would change, or an NVD snapshot recorded with other values, stops the reader; a person decides. Nothing is written unless every check passes.
- **Oversized or redirected responses**: 30 second timeout, 20 MB cap counted while reading, redirects refused.
- **Misreading**: overlapping NVD 24-hour snapshots are kept one by one and never added up; every figure says "worldwide", names its source and licence, carries NVD's notice where NVD is used, and says that counts reflect catalogue activity, not how secure anyone is.
- **Stale data**: each point carries the time it was read. Not yet built: marking a source stale on the page when it has not been read for 8 days.
