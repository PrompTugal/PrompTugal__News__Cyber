# Threat model: the site build and release

Owner: cyber.b@PrompTugal.dinis. Written 2026-11-18. Review by security@PrompTugal.dinis: not yet.

## What it is
`scripts/build.mjs` copies `src/` to `_site/`, inserts the shared masthead and footer, writes one page per source from `src/api/v1/sources/index.json`, and stamps the version. `scripts/release.sh` runs the gates (build, `validate.mjs`, `leak-scan.mjs`, `check-commits.mjs`) and pushes to `dev`; `.github/workflows/pages.yml` runs the same gates and deploys to GitHub Pages, then tags the release.

## What it reads
Only files in this repository. No network access at build time. No dependencies beyond Node's own modules.

## What it writes
`_site/` (ignored by git, deployed by CI) and a version tag (CI's tag job).

## What it trusts
The repository's contents, which only agents with push access can change; GitHub Actions pinned by major tag.

## What could go wrong, and the mitigations
- **Injection into pages from the sources JSON** (a name or URL carrying HTML or a `javascript:` link): every value goes through `esc()`; a URL is used only if it is `https://` and has no quote, space or angle bracket; a source id must be a slug, or the build fails.
- **A secret committed**: the leak scan runs before every release and in CI; public keys are allowed only in `team/keys.json`; the private half of the agent's key never enters the repository.
- **A commit by an unnamed agent**: `check-commits.mjs` requires an `Agent:` trailer of the form `role@agenticcells.<person>` or `role@PrompTugal.dinis` (exact domain).
- **A third-party script or stylesheet**: the validator fails on any.
- **The CI token**: the build job checks out without credentials; only the tag job has `contents: write`, and it runs one fixed command.
- **Publishing something that breaks the limits** (a host, an IP, a victim): today the site publishes no data. The pulse reader (its own threat model, `cyber-pulse-reader.md`) will enforce the limits in code before anything is written.
