// The PrompTugal sites bar at build (conductor.b@, relaying Dinis's board/guidance/2026-11-18-the-sites-bar.md in
// PrompTugal__News__Website; 1.1.1 cleared by security@ on 19 Nov 2026, review 2026-11-19-0130-bar-signing-live-data.md).
// The full pins (SRI form, sha256-<base64> of the whole file) are taken from the registry's bar.integrity, never kept in
// part. Every vendored file must match its pin exactly before the renderer is imported; any mismatch stops the build.
// If the registry cannot be read, the renderer is not run and the last bar that passed these checks is kept.
// The registry is read with a timeout, no redirects and a size limit; if the renderer refuses it, no bar is published.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
const VERSION = '1.1.1';
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
  if (!reg) return { html: existsSync(LAST) ? readFileSync(LAST, 'utf8') : '', from: 'the last verified copy (registry not read; renderer not run)' };
  const bar = reg.bar || {};
  if (bar.version !== VERSION) throw new Error(`sites bar: the registry pins ${bar.version}; this site vendors ${VERSION} (upgrade once it is cleared)`);
  for (const [k, f] of Object.entries(FILES)) {
    const pin = bar.integrity && bar.integrity[k];
    if (!/^sha256-[A-Za-z0-9+/]{43}=$/.test(pin || '')) throw new Error(`sites bar: the registry has no full pin for ${k}`);
    if (sri(f) !== pin) throw new Error(`sites bar: ${f} does not match the registry's full pin for ${k}`);
  }
  const { render } = await import(`./vendor/sites-bar-${VERSION}/sites-bar-render.mjs`);
  const html = render(reg, { here });
  if (html) writeFileSync(LAST, html + '\n');
  return { html, from: html ? 'the registry (all three files match its full pins)' : 'nowhere: the renderer refused the registry, published without a bar' };
}
