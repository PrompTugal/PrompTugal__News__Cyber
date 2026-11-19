// The PrompTugal sites bar 1.1.0 at build (conductor.b@, 19 Nov 2026, relaying Dinis's
// board/guidance/2026-11-18-the-sites-bar.md in PrompTugal__News__Website). Reads the registry
// https://promptugal.news/api/v1/sites.json, checks that the vendored files are the ones it pins, and renders the bar with
// the vendored renderer (never loaded from promptugal.news). If the registry cannot be read, the last good bar is kept
// (scripts/vendor/sites-bar-1.1.0/last-bar.html); if the renderer refuses it, the site is published without a bar.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
const REGISTRY = 'https://promptugal.news/api/v1/sites.json';
const LAST = 'scripts/vendor/sites-bar-1.1.0/last-bar.html';
// The first 16 hex characters of each file's sha256 (the full values are in the registry's bar.sha256, checked below).
const PIN = {
  'scripts/vendor/sites-bar-1.1.0/sites-bar-render.mjs': ['render', 'b9b50ae32fd5dc23'],
  'src/assets/sites-bar/1.1.0/sites-bar.css': ['css', '302e2544eb34e3d6'],
  'src/assets/sites-bar/1.1.0/sites-bar.js': ['js', 'bc97a820a8f4fbda'],
};
const sha = f => createHash('sha256').update(readFileSync(f)).digest('hex');
for (const [f, [, h]] of Object.entries(PIN)) if (!sha(f).startsWith(h)) throw new Error(`sites bar: ${f} is not the pinned 1.1.0 file`);
// Imported only after its hash is checked (AppSec post-review, 19 Nov 2026).
const { render } = await import('./vendor/sites-bar-1.1.0/sites-bar-render.mjs');
export async function sitesBar(here) {
  let reg = null;
  try {
    const r = await fetch(REGISTRY, { redirect: 'error', signal: AbortSignal.timeout(10_000), headers: { accept: 'application/json' } });
    const len = Number(r.headers.get('content-length') || 0);
    const t = r.ok && len < 512 * 1024 ? await r.text() : '';
    if (t.length > 0 && t.length < 512 * 1024) reg = JSON.parse(t);
  } catch { reg = null; }
  if (!reg) return { html: existsSync(LAST) ? readFileSync(LAST, 'utf8') : '', from: 'the last good copy (registry not read)' };
  if (reg.bar && reg.bar.version && reg.bar.version !== '1.1.0') console.warn(`sites bar: the registry pins ${reg.bar.version}; this site vendors 1.1.0`);
  if (reg.bar && reg.bar.version === '1.1.0' && reg.bar.sha256) for (const [f, [k]] of Object.entries(PIN)) { const want = reg.bar.sha256[k]; if (want && sha(f) !== want) throw new Error(`sites bar: ${f} differs from the registry's sha256 for 1.1.0`); }
  const html = render(reg, { here });
  if (html) writeFileSync(LAST, html + '\n');
  return { html, from: html ? 'the registry' : 'nowhere: the renderer refused the registry, published without a bar' };
}
