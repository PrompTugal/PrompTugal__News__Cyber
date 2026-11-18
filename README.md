# PrompTugal.news Cyber

**Domain:** https://cyber.promptugal.news

**Focus:** Cyber security and threat intelligence for PrompTugal.news. (In Dinis's words, 2026-11-18: "we're going to capture a lot of threat intelligence data on the other side".)

Part of [PrompTugal.news](https://promptugal.news/) (Portugal, town by town).

## Status
A placeholder: first version coming. Built by the PrompTugal.news team.

## How it works
- `dev` is the default branch. Every push to `dev` builds the site from `src/` and deploys it to GitHub Pages (`.github/workflows/pages.yml`), with the version at https://cyber.promptugal.news/version.json.
- `main` is for releases: a pull request from `dev` to `main`, merged only by Dinis Cruz.
- Public, like every repository the factory creates. No secrets in this repository; `.credentials/` and `.sg-send/` are ignored by git.

## What never goes in this public repository
- Live malware or exploit code.
- Leaked or stolen credentials or data, not even redacted samples.
- Personal data about victims.
- Indicators are published only from public sources, each with its source and date. Anything else stays in an sgit vault.

Made by the AgentiCCells site factory, request `requests/2026-11-18__cyber-promptugal-news/` in AgentiCCells/AgentiCCells__Site__Factory.

## Licences
- Code: Apache-2.0, in `LICENSE`.
- Text, guidance and images: CC BY 4.0, in `LICENSE-TEXT`.
