// The PrompTugal sites bar at build (conductor.b@, relaying Dinis's board/guidance/2026-11-18-the-sites-bar.md in
// PrompTugal__News__Website; 1.1.1 cleared by security@ on 19 Nov 2026, review 2026-11-19-0130-bar-signing-live-data.md; 1.2.0 cleared by security@, Website 055e6c1430, wake 07:03 UTC 19 Nov 2026).
// The full pins (SRI form, sha256-<base64> of the whole file) are taken from the registry's bar.integrity, never kept in
// part. Every vendored file must match its pin exactly before the renderer is imported; any mismatch stops the build.
// If the registry cannot be read, the renderer is not run and the last bar that passed these checks is kept.
// If the registry names another version, the site is published without a bar (and without its CSS and JS) until upgraded.
// The registry is read with a timeout, no redirects and a size limit; if the renderer refuses it, no bar is published.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
const VERSION = '1.2.0';
const REGISTRY = 'https://promptugal.news/api/v1/sites.json';
const LAST = `scripts/vendor/sites-bar-${VERSION}/last-bar.html`;
export const TEMPLATE = `scripts/vendor/sites-bar-${VERSION}/preview-template.svg.txt`;
export const ASSETS = `/assets/sites-bar/${VERSION}`;
const FILES = {
  render: `scripts/vendor/sites-bar-${VERSION}/sites-bar-render.mjs`,
  css: `src/assets/sites-bar/${VERSION}/sites-bar.css`,
  js: `src/assets/sites-bar/${VERSION}/sites-bar.js`,
};
const sri = f => 'sha256-' + createHash('sha256').update(readFileSync(f)).digest('base64');
export async function sitesBar(here) {
  let reg = null;
  try {
    const r = await fetch(REGISTRY, { redirect: 'error', signal: AbortSignal.timeout(10_000), headers: { accept: 'application/json' } });
    const len = Number(r.headers.get('content-length') || 0);
    const t = r.ok && len < 512 * 1024 ? await r.text() : '';
    if (t.length > 0 && t.length < 512 * 1024) reg = JSON.parse(t);
  } catch { reg = null; }
  if (!reg) return { html: existsSync(LAST) ? readFileSync(LAST, 'utf8') : '', assets: existsSync(LAST), from: 'the last verified copy (registry not read; renderer not run)' };
  const bar = reg.bar || {};
  // A newer (or other) version in the registry is not a reason to stop the site (conductor.b@, 19 Nov 2026, 05:10 UTC,
  // from data.b@'s finding; confirmed by security@, Website 1acd10498). If the registry still keeps this version's pins
  // (bar.versions[VERSION].integrity, dev@'s append-only proposal), they are checked as usual. Otherwise the bar is left
  // out, never shipped unchecked, and the log says so in security@'s words. The same version with other bytes still stops.
  const pins = bar.version === VERSION ? bar.integrity : (bar.versions && bar.versions[VERSION] && bar.versions[VERSION].integrity);
  if (!pins) {
    const off = `sites bar ${VERSION} off: the registry names ${String(bar.version).slice(0, 20)}`;
    console.warn(off);
    return { html: '', assets: false, off, from: `nowhere (${off})` };
  }
  for (const [k, f] of Object.entries(FILES)) {
    const pin = pins[k];
    if (!/^sha256-[A-Za-z0-9+/]{43}=$/.test(pin || '')) throw new Error(`sites bar: the registry has no full pin for ${k}`);
    if (sri(f) !== pin) throw new Error(`sites bar: ${f} does not match the registry's full pin for ${k}`);
  }
  const { render } = await import(`./vendor/sites-bar-${VERSION}/sites-bar-render.mjs`);
  const html = render(reg, { here });
  if (html) writeFileSync(LAST, html + '\n');
  return { html, assets: !!html, from: html ? 'the registry (all three files match its full pins)' : 'nowhere: the renderer refused the registry, published without a bar' };
}
