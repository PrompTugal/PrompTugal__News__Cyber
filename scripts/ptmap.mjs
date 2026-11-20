// The shared map, ptmap (designer@PrompTugal.dinis; Dinis, 19 Nov 2026, about 17:40 UTC: "Portugal big", London and the EU
// small). Vendored from PrompTugal__News__Website design/shared-map/v1.0.2/ (commit 758810f86) into src/assets/ptmap/1.0.2/.
// As with the sites bar, no pin is kept in this repository (the leak scan reads a full SRI value as a possible secret, and
// the scan is not weakened): every build reads the registry's map.versions["1.0.2"] and needs its review to start "passed"
// and both files to match its full sha384 pins. A pin that differs, or a malformed entry, stops the build. A registry that
// cannot be read, or that no longer lists or passes this version, leaves the map out of that build (logged), never shipped
// unchecked. cyber.b@PrompTugal.dinis, 20 Nov 2026.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

export const VERSION = '1.0.2';
export const ASSETS = `/assets/ptmap/${VERSION}`;
const FILES = ['ptmap.js', 'ptmap.css'];
const REGISTRY = 'https://promptugal.news/api/v1/sites.json';
const sri = f => 'sha384-' + createHash('sha384').update(readFileSync(f)).digest('base64');

// reg: the parsed registry, or null when it could not be read; dir: where the vendored files are
export function decide(reg, dir = `src/assets/ptmap/${VERSION}`) {
  if (!reg) return { on: false, from: 'nowhere: the registry was not read, so the pins could not be checked (map off)' };
  const listed = reg.map && reg.map.versions && typeof reg.map.versions === 'object' ? reg.map.versions[VERSION] : undefined;
  if (listed === undefined || listed === null) return { on: false, from: `nowhere: the registry no longer lists ptmap ${VERSION} (map off)` };
  if (typeof listed !== 'object' || Array.isArray(listed) || !listed.integrity || typeof listed.integrity !== 'object' || Array.isArray(listed.integrity)) throw new Error(`ptmap: the registry's entry for ${VERSION} has no pin map`);
  if (!/^passed( \(|$)/.test(String(listed.review || ''))) return { on: false, from: `nowhere: the registry's review of ptmap ${VERSION} does not start "passed" (map off)` };
  for (const k of FILES) {
    const pin = listed.integrity[k];
    if (!/^sha384-[A-Za-z0-9+/]{64}$/.test(pin || '')) throw new Error(`ptmap: the registry has no full pin for ${k}`);
    if (sri(`${dir}/${k}`) !== pin) throw new Error(`ptmap: ${dir}/${k} does not match the registry's pin`);
  }
  return { on: true, from: `the vendored copy, matching the registry's pins (${String(listed.review).slice(0, 60)})` };
}

export async function ptmap() {
  let reg = null;
  try {
    const r = await fetch(REGISTRY, { redirect: 'error', signal: AbortSignal.timeout(10_000), headers: { accept: 'application/json' } });
    const t = r.ok ? await r.text() : '';
    if (t.length > 0 && t.length < 512 * 1024) reg = JSON.parse(t);
  } catch { reg = null; }
  return decide(reg);
}
