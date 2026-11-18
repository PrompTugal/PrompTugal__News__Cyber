# REALITY.md: what exists now

- Seeded by the AgentiCCells site factory on 2026-11-18 from AgentiCCells/AgentiCCells__Site__Template@dev.
- Its live state is recorded in requests/2026-11-18__cyber-promptugal-news/status.json in AgentiCCells__Site__Factory.
- 2026-11-18: cells@AgentiCCells.dinis, at Dinis's word (~15:50 UTC), replaced the seed page with a placeholder, wrote the README (with what never goes in this public repository), added `LICENSE-TEXT` (CC BY 4.0) beside `LICENSE` (Apache-2.0), added `src/CNAME`, ignored `.credentials/` and `.sg-send/`, and created `main` from this commit. The factory's collaborators step found `riskmandate-agent` already had write access.
- 2026-11-18, about 20:50 to 22:00 UTC: cyber.b@PrompTugal.dinis (lead of this site, started by conductor.b@PrompTugal.dinis at Dinis's word) made the first version:
  - **Its key:** made with `sgit pki keygen`; the public bundle is in `team/keys.json` (id `cyber.b-promptugal`). Not yet in PrompTugal__News__Website's `board/keys.json` (conductor.b@ lists it).
  - **The commit check** (`scripts/check-commits.mjs`) also accepts `role@PrompTugal.dinis` agents, exact domain, as in the five site repositories at Dinis's word. Its own commit; flagged to conductor.b@ and Dinis.
  - **The site:** the pulse (`/`) with **no figures**: no source has been collected yet. `/how/` (the limits), `/sources/` and one page per source (CISA KEV, NVD, CVE.org, ENISA: terms checked on data.b@'s register, all "awaiting collection"; the sources not read and why), `/security/` (no findings yet), `/api/` with `/api/openapi.json`, `/api/v1/pulse/index.json` (state "awaiting data", no series) and `/api/v1/sources/index.json`. Masthead, sites rail and footer (principles, report, take-down disclaimer, licences) as on data.promptugal.news. Brand files and CSS copied from data.promptugal.news (`CREDITS.md`).
  - **Threat models:** `docs/threat-models/site-build.md`; `docs/threat-models/cyber-pulse-reader.md` is a draft, for code not yet written.
  - **Does not exist yet:** any collected data or figure; the pulse reader; a scheduled rebuild; per-source OpenAPI files; the vendors-relevant-to-Portugal list; totals by sector (a proposal); obs.js (no lane yet); this site on the reading meter (not decided).
  - Board: `board/team/cyber/status.json` and `board/team/cyber/debriefs/2026-11-18-handover.md`.
