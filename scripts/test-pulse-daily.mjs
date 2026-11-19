// Tests for the pulse reader's daily NVD totals (security pre-review, 19 Nov 2026, about 10:20 UTC). Each case runs
// scripts/pulse-read.mjs --from on a crafted copy of the live-shaped files, in a temporary directory, and asserts the
// reason it stops (or that it passes). Nothing in the repository is touched. Prints OK or the failing cases and exits 1.
import { mkdtempSync, mkdirSync, writeFileSync, cpSync, rmSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const root = new URL('..', import.meta.url).pathname;
const day = n => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10);
const now = new Date(Date.now() - 60_000).toISOString().replace(/\.\d+Z$/, 'Z');
const bands = (c, h, m, l, n, u) => ({ CRITICAL: c, HIGH: h, MEDIUM: m, LOW: l, NONE: n, unscored: u });
const entry = (total, b, extra = {}) => ({ new: total, modified: 0, by_severity: { new: b, modified: bands(0, 0, 0, 0, 0, 0) }, complete: true, counted_at: now, ...extra });
const kev = { read_at: now, vulnerabilities: [{ cveID: 'CVE-2024-0001', dateAdded: day(3) }] };
const nvd = dt => ({ read_at: now, last_24h: { new: 6, new_by_severity: bands(1, 1, 1, 1, 1, 1) }, daily_totals: dt });

const euvdOk = (over = {}) => ({ source: 'euvd', schema: { version: 'v1' }, read_at: now, last_24h: { new: 6, new_by_severity: bands(1, 1, 1, 1, 1, 1), exploited: 2 }, counts: { in_last_24h: 10, exploited_in_last_24h: 2, exploited_total_euvd: 100 }, daily_totals: {}, ...over });
function run(dt, hist, euvd, euvdHist) {
  const dir = mkdtempSync(join(tmpdir(), 'pulse-test-'));
  try {
    mkdirSync(join(dir, 'scripts')); cpSync(join(root, 'scripts/pulse-read.mjs'), join(dir, 'scripts/pulse-read.mjs'));
    mkdirSync(join(dir, 'src/api/v1/pulse/history'), { recursive: true });
    if (hist) writeFileSync(join(dir, 'src/api/v1/pulse/history/nvd-daily.json'), JSON.stringify({ points: hist }));
    mkdirSync(join(dir, 'in'));
    if (euvd) writeFileSync(join(dir, 'in/euvd.json'), JSON.stringify(euvd));
    if (euvdHist) writeFileSync(join(dir, 'src/api/v1/pulse/history/euvd-24h.json'), JSON.stringify({ points: euvdHist }));
    writeFileSync(join(dir, 'in/cisa-kev.json'), JSON.stringify(kev)); writeFileSync(join(dir, 'in/nvd-cve.json'), JSON.stringify(dt === undefined ? nvd(undefined) : nvd(dt)));
    const r = spawnSync('node', ['scripts/pulse-read.mjs', '--from', 'in'], { cwd: dir, encoding: 'utf8' });
    const out = r.status === 0 ? JSON.parse(readFileSync(join(dir, 'src/api/v1/pulse/history/nvd-daily.json'), 'utf8')) : null;
    return { ok: r.status === 0, err: r.stderr.trim(), out };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
const kept = (d, t) => ({ day: d, total: t, by_band: Object.fromEntries(Object.entries(bands(t, 0, 0, 0, 0, 0)).map(([k, v]) => [k, { total: v }])), counted_at: now });
const cases = [
  ['a good complete day is kept', { [day(1)]: entry(6, bands(1, 1, 1, 1, 1, 1)) }, null, r => r.ok && r.out.points.length === 1 && r.out.points[0].total === 6],
  ['the open day is not kept', { [day(0)]: entry(6, bands(1, 1, 1, 1, 1, 1), { complete: false }) }, null, r => r.ok && r.out.points.length === 0],
  ['complete must be strictly true', { [day(1)]: entry(6, bands(1, 1, 1, 1, 1, 1), { complete: 'true' }) }, null, r => r.ok && r.out.points.length === 0],
  ['no daily_totals is fine', undefined, null, r => r.ok],
  ['a future day stops', { [day(-2)]: entry(6, bands(1, 1, 1, 1, 1, 1)) }, null, r => !r.ok && /not a real past or present/.test(r.err)],
  ['2026-02-30 stops', { '2026-02-30': entry(6, bands(1, 1, 1, 1, 1, 1)) }, null, r => !r.ok && /not a real past or present/.test(r.err)],
  ['today marked complete stops', { [day(0)]: entry(6, bands(1, 1, 1, 1, 1, 1)) }, null, r => !r.ok && /before it has ended/.test(r.err)],
  ['an extra band stops', { [day(1)]: entry(6, { ...bands(1, 1, 1, 1, 1, 1), EXTRA: 0 }) }, null, r => !r.ok && /bands/.test(r.err)],
  ['bands not adding up stops', { [day(1)]: entry(7, bands(1, 1, 1, 1, 1, 1)) }, null, r => !r.ok && /bands/.test(r.err)],
  ['a counted_at in the future stops', { [day(1)]: entry(6, bands(1, 1, 1, 1, 1, 1), { counted_at: '2099-01-01T00:00:00Z' }) }, null, r => !r.ok && /counted_at/.test(r.err)],
  ['a counted_at inside the day stops', { [day(1)]: entry(6, bands(1, 1, 1, 1, 1, 1), { counted_at: day(1) + 'T12:00:00Z' }) }, null, r => !r.ok && /counted_at/.test(r.err)],
  ['a huge total stops', { [day(1)]: entry(60000, bands(60000, 0, 0, 0, 0, 0)) }, null, r => !r.ok && /no valid total/.test(r.err)],
  ['too many days stops', Object.fromEntries(Array.from({ length: 61 }, (_, i) => [day(i + 1), entry(6, bands(1, 1, 1, 1, 1, 1))])), null, r => !r.ok && /more than 60 days/.test(r.err)],
  ['a __proto__ key stops', JSON.parse('{"__proto__": {"complete": true}}'), null, r => !r.ok && /not a real past or present/.test(r.err)],
  ['a changed complete day stops', { [day(2)]: entry(6, bands(6, 0, 0, 0, 0, 0)) }, [kept(day(2), 5)], r => !r.ok && /changed; not overwriting/.test(r.err)],
  ['a day dropped inside the window stops', { [day(3)]: entry(6, bands(6, 0, 0, 0, 0, 0)), [day(1)]: entry(6, bands(6, 0, 0, 0, 0, 0)) }, [kept(day(3), 6), kept(day(2), 4), kept(day(1), 6)], r => !r.ok && /missing from a read that covers it/.test(r.err)],
  ['an empty read with a recent kept day stops', {}, [kept(day(2), 6)], r => !r.ok && /missing from a read that covers it/.test(r.err)],
  ['the earliest recent kept day dropped stops', { [day(1)]: entry(6, bands(6, 0, 0, 0, 0, 0)) }, [kept(day(5), 6), kept(day(1), 6)], r => !r.ok && /missing from a read that covers it/.test(r.err)],
  ['a broken kept point stops', { [day(1)]: entry(6, bands(6, 0, 0, 0, 0, 0)) }, [{ day: day(40), total: 1 }], r => !r.ok && /kept daily history fails/.test(r.err)],
  ['a day older than the window stays', { [day(1)]: entry(6, bands(6, 0, 0, 0, 0, 0)) }, [kept(day(40), 9)], r => r.ok && r.out.points.length === 2 && r.out.points[0].total === 9],
];
const g = { [day(1)]: entry(6, bands(6, 0, 0, 0, 0, 0)) };
const eSnap = (t, at) => ({ read_at: at, window_hours: 24, total: 6, by_band: Object.fromEntries(Object.entries(bands(6, 0, 0, 0, 0, 0)).map(([k, v]) => [k, { total: v }])), exploited_24h: 2, exploited_total: t });
cases.push(
  ['EUVD: a good file is kept as one snapshot', g, null, r => r.ok, euvdOk()],
  ['EUVD: not the euvd v1 file stops', g, null, r => !r.ok && /euvd: not the euvd v1 file/.test(r.err), euvdOk({ source: 'nvd' })],
  ['EUVD: bands not adding up stop', g, null, r => !r.ok && /euvd: last_24h/.test(r.err), euvdOk({ last_24h: { new: 7, new_by_severity: bands(1, 1, 1, 1, 1, 1), exploited: 2 } })],
  ['EUVD: exploited counts that disagree stop', g, null, r => !r.ok && /exploited count is not consistent/.test(r.err), euvdOk({ counts: { in_last_24h: 10, exploited_in_last_24h: 3, exploited_total_euvd: 100 } })],
  ['EUVD: an exploited total below the 24-hour count stops', g, null, r => !r.ok && /exploited total is out of bounds/.test(r.err), euvdOk({ counts: { in_last_24h: 10, exploited_in_last_24h: 2, exploited_total_euvd: 1 } })],
  ['EUVD: a fall of more than 2% in the exploited total stops', g, null, r => !r.ok && /more than 2% below the highest kept/.test(r.err), euvdOk(), [eSnap(200, '2026-01-01T00:00:00Z')]],
  ['EUVD: a slow ratchet down is caught against the highest kept', g, null, r => !r.ok && /more than 2% below the highest kept/.test(r.err), euvdOk({ counts: { in_last_24h: 10, exploited_in_last_24h: 2, exploited_total_euvd: 100 } }), [eSnap(110, '2026-01-01T00:00:00Z'), eSnap(103, '2026-01-02T00:00:00Z')]],
  ['EUVD: a jump of more than half stops', g, null, r => !r.ok && /rose by more than half/.test(r.err), euvdOk({ counts: { in_last_24h: 10, exploited_in_last_24h: 2, exploited_total_euvd: 1000 } }), [eSnap(100, '2026-01-01T00:00:00Z')]],
  ['EUVD: the same instant in another spelling is not a new point', g, null, r => !r.ok && /already recorded with other values/.test(r.err), euvdOk({ read_at: now.replace('Z', '.000Z') }), [eSnap(99, now)]],
  ['EUVD: an older read stops', g, null, r => !r.ok && /euvd: this read is older/.test(r.err), euvdOk(), [eSnap(100, '2099-01-01T00:00:00Z')]],
  ['EUVD: a changed kept snapshot stops', g, null, r => !r.ok && /already recorded with other values/.test(r.err), euvdOk(), [eSnap(99, now)]],
  ['EUVD: a bad complete day stops, naming the source', g, null, r => !r.ok && /euvd: day .* bands/.test(r.err), euvdOk({ daily_totals: { [day(1)]: entry(7, bands(1, 1, 1, 1, 1, 1)) } })],
);
const bad = [];
for (const [name, dt, hist, ok, euvd, eh] of cases) { const r = run(dt, hist, euvd, eh); if (!ok(r)) bad.push(`FAIL ${name}: ${r.ok ? 'passed' : r.err.slice(0, 160)}`); }
if (bad.length) { console.error(bad.join('\n')); console.error(`FAILED (${bad.length} of ${cases.length})`); process.exit(1); }
console.log(`OK (${cases.length} daily-totals cases)`);
