# Threat model: the data explorer (/explore/)

Owner: cyber.b@PrompTugal.dinis. Written 2026-11-19. Review by security@PrompTugal.dinis: not yet.

## What it is
A page whose script (`src/assets/explore/explore.js`, our own code, no build step) runs in the reader's browser. It fetches three JSON files by GET (`data.promptugal.news/api/v1/cisa-kev/latest.json`, `data.promptugal.news/api/v1/nvd-cve/latest.json`, this site's `/api/v1/pulse/index.json`), draws charts and a graph as SVG, shows browsable tables, and loads the rows into SQLite in the browser (sql.js 1.10.3, MIT, vendored at `src/assets/vendor/sql.js-1.10.3/`, the npm tarball checked against npm's sha512) so the reader can query them with SQL and download a CSV. Nothing is sent anywhere; no cookies, no storage. Filters live in the address (`#tab=kev&vendor=...`); values from the address are only compared with the data as plain strings or checked against fixed patterns, and shown with `textContent`.

## What it trusts
Our own code and the vendored sql.js. Not the data: the JSON carries third-party text (vendor, product, CNA names, vulnerability names).

## What could go wrong, and the mitigations
- **Script injection from the data**: third-party text is set only with `textContent` or as SVG text nodes; the file has no `innerHTML`. Strings are cut to a maximum length. The only links built from data are to `https://nvd.nist.gov/vuln/detail/<id>`, and only for ids matching `CVE-YYYY-NNNN`.
- **A compromised or wrong data host**: a Content-Security-Policy on the page allows scripts only from this site (plus WebAssembly for SQLite), connections only to this site and data.promptugal.news, no plugins, no forms, no base changes. Fetches refuse redirects and send no credentials.
- **The reader's own SQL**: it runs in an in-memory database in their browser, holding only public data; it cannot reach the network or any file. Query text is capped at 5,000 characters and results shown at 1,000 rows.
- **CSV injection** when a downloaded CSV is opened in a spreadsheet: values starting with `=`, `+`, `-`, `@`, a tab or a carriage return are prefixed with a quote.
- **The vendored library changing**: it is pinned by version in its path, its source and hash are in `CREDITS.md`, and it is never fetched from a third party at run time.
- **The limits**: the data holds products and vendors, never hosts, IPs, devices or victims; the page says the counts are worldwide catalogue activity, not a rating of anyone.
