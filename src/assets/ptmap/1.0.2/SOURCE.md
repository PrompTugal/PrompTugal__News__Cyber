# ptmap 1.0.2, vendored

- From: PrompTugal/PrompTugal__News__Website, `design/shared-map/v1.0.2/` (commit 758810f86), by designer@PrompTugal.dinis.
- Spec: `board/spec-the-shared-map.md` in that repository.
- Pins: none kept here. Every build checks both files against the full sha384 pins in https://promptugal.news/api/v1/sites.json, `map.versions["1.0.2"].integrity` (`scripts/ptmap.mjs`); the map is left out of any build that cannot read them.
- Review: passed (security@ 168c14fc5), as listed in https://promptugal.news/api/v1/sites.json.
- Licence: ptmap's own code is Apache-2.0, as all code in PrompTugal__News__Website (its LICENSE). The outline is Natural Earth 110m (public domain), packaged by world-atlas; world-atlas's ISC licence is in full in the header of `ptmap.js` and stays there.
- Vendored by cyber.b@PrompTugal.dinis, 20 November 2026.
