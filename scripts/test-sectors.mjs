// Tests for the proposed sector mapping (scripts/sectors.mjs): each fault in the hand-written mapping stops the build, a rule
// for a product beats one for its vendor, and the shipped mapping passes against the CVE store. Prints OK or the failing
// cases and exits 1. cyber.b@PrompTugal.dinis, 21 Nov 2026.
import { readFileSync } from 'node:fs';
import { check, classify, loadKev } from './sectors.mjs';
const kev = [{ id: 'CVE-2020-0001', vendor: 'Acme', product: 'Plc' }, { id: 'CVE-2020-0002', vendor: 'Acme', product: 'Mail' }, { id: 'CVE-2020-0003', vendor: 'Other', product: 'X' }];
const base = () => ({ status: 'proposal', about: 'a', notice: 'n', by: 'b', made: 'm', from: 'f', precedence: 'p', classes: [{ id: 'industrial-control', name: 'I', typical_use: ['energy'], reason: 'r' }, { id: 'general-it', name: 'G', typical_use: ['every sector'], reason: 'r' }],
  rules: [{ vendor: 'Acme', product: '*', class: 'general-it', reason: 'r', evidence: 'e' }, { vendor: 'Acme', product: 'Plc', class: 'industrial-control', reason: 'r', evidence: 'e' }] });
const cases = []; const expect = (name, ok, got) => cases.push({ name, ok, got });
const fails = (name, mut, re) => { const m = base(); mut(m); let e = ''; try { check(m, kev); } catch (x) { e = String(x.message); } expect(name, re.test(e), e || 'no error'); };
let c = classify(base(), kev); expect('a product rule beats its vendor rule; the rest is not classed yet', c.counts['industrial-control'] === 1 && c.counts['general-it'] === 1 && c.none === 1, JSON.stringify(c.counts) + c.none);
fails('a status other than proposal stops the build', m => { m.status = 'final'; }, /status "proposal"/);
fails('an unknown class stops the build', m => { m.rules[0].class = 'health'; }, /unknown class/);
fails('a rule listed twice stops the build', m => { m.rules.push({ ...m.rules[0] }); }, /listed twice/);
fails('a rule without a reason stops the build', m => { delete m.rules[1].reason; }, /without a reason: Acme Plc/);
fails('a rule without evidence stops the build', m => { m.rules[1].evidence = ''; }, /without evidence: Acme Plc/);
fails('a vendor not on KEV now stops the build (stale rule)', m => { m.rules.push({ vendor: 'Gone', product: '*', class: 'general-it', reason: 'r', evidence: 'e' }); }, /stale/);
fails('a product not on KEV now stops the build (stale rule)', m => { m.rules[1].product = 'Old'; }, /stale/);
fails('a vendor matched in another case is not the same vendor', m => { m.rules[0].vendor = 'acme'; }, /stale/);
fails('a class without sectors stops the build', m => { m.classes[0].typical_use = []; }, /bad class/);
fails('a mapping without its notice stops the build', m => { delete m.notice; }, /no notice/);
const real = JSON.parse(readFileSync('src/api/v1/sectors/mapping.json', 'utf8')); let err = '';
try { check(real, loadKev()); } catch (x) { err = String(x.message); }
expect('the shipped mapping passes against the CVE store', !err, err);
const bad = cases.filter(x => !x.ok);
if (bad.length) { for (const x of bad) console.error(`FAIL ${x.name}: ${String(x.got).slice(0, 300)}`); console.error(`FAILED (${bad.length} of ${cases.length})`); process.exit(1); }
console.log(`OK (${cases.length} sector-mapping cases)`);
