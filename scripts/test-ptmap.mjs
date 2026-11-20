// Tests for the shared map's checks (scripts/ptmap.mjs): the registry decides, pins are computed here from the vendored
// files (none is kept in the repository). Prints OK or the failing cases and exits 1. cyber.b@PrompTugal.dinis, 20 Nov 2026.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { decide, VERSION } from './ptmap.mjs';
const dir = `src/assets/ptmap/${VERSION}`;
const pin = f => 'sha384-' + createHash('sha384').update(readFileSync(`${dir}/${f}`)).digest('base64');
const good = () => ({ map: { versions: { [VERSION]: { review: 'passed (security@ test)', integrity: { 'ptmap.js': pin('ptmap.js'), 'ptmap.css': pin('ptmap.css') } } } } });
const cases = []; const expect = (name, ok, got) => cases.push({ name, ok, got });
const run = reg => { try { return { r: decide(reg) }; } catch (e) { return { e: String(e.message) }; } };
let x = run(good()); expect('matching pins and a passed review: on', x.r && x.r.on, JSON.stringify(x));
x = run(null); expect('registry not read: off, not shipped unchecked', x.r && !x.r.on && /not read/.test(x.r.from), JSON.stringify(x));
x = run({ map: { versions: {} } }); expect('version no longer listed: off', x.r && !x.r.on && /no longer lists/.test(x.r.from), JSON.stringify(x));
x = run({}); expect('no map in the registry: off', x.r && !x.r.on, JSON.stringify(x));
let g = good(); g.map.versions[VERSION].review = 'pending: security@'; x = run(g); expect('review not passed: off', x.r && !x.r.on && /passed/.test(x.r.from), JSON.stringify(x));
g = good(); g.map.versions[VERSION].integrity['ptmap.js'] = 'sha384-' + 'A'.repeat(64); x = run(g); expect('a different pin stops the build', x.e && /does not match/.test(x.e), JSON.stringify(x));
g = good(); g.map.versions[VERSION].integrity['ptmap.css'] = 'sha256-abc'; x = run(g); expect('a short or other pin stops the build', x.e && /no full pin/.test(x.e), JSON.stringify(x));
g = good(); g.map.versions[VERSION] = 'yes'; x = run(g); expect('a malformed entry stops the build', x.e && /no pin map/.test(x.e), JSON.stringify(x));
g = good(); delete g.map.versions[VERSION].integrity['ptmap.css']; x = run(g); expect('a missing pin stops the build', x.e && /no full pin/.test(x.e), JSON.stringify(x));
g = good(); g.map.versions[VERSION].review = 'passed-not (test)'; x = run(g); expect('a review that only begins with the word passed: off', x.r && !x.r.on, JSON.stringify(x));
const js = readFileSync(`${dir}/ptmap.js`, 'utf8');
expect('the ISC licence stays in full in the vendored file', js.includes('Copyright 2013-2019 Michael Bostock') && js.includes('Permission to use, copy, modify, and/or distribute this software') && js.includes('THIS SOFTWARE.'), 'ptmap.js header');
const bad = cases.filter(c => !c.ok);
if (bad.length) { for (const c of bad) console.error(`FAIL ${c.name}: ${String(c.got).slice(0, 300)}`); console.error(`FAILED (${bad.length} of ${cases.length})`); process.exit(1); }
console.log(`OK (${cases.length} shared-map cases)`);
