// The pulse reader (cyber.b@PrompTugal.dinis, 2026-11-18). Threat model: docs/threat-models/cyber-pulse-reader.md.
// Reads data.b@PrompTugal.dinis's published JSON on data.promptugal.news (untrusted input), counts, and writes
// only integers, ISO dates and our own fixed labels into src/api/v1/pulse/. Run by the site lead before a release;
// it is not run by CI yet. Node built-ins only.
//   node scripts/pulse-read.mjs            fetch both sources, update the history, rewrite the pulse
//   node scripts/pulse-read.mjs --from DIR read DIR/cisa-kev.json and DIR/nvd-cve.json instead (for tests)
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'node:fs';

const SOURCES = {
  kev: 'https://data.promptugal.news/api/v1/cisa-kev/latest.json',
  nvd: 'https://data.promptugal.news/api/v1/nvd-cve/latest.json',
};
const MAX_BYTES = 20 * 1024 * 1024;
const BANDS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'unscored'];
const DIR = 'src/api/v1/pulse';
const HIST = `${DIR}/history`;
const NVD_NOTICE = 'This product uses the NVD API but is not endorsed or certified by the NVD.';
const CAVEAT = 'Worldwide totals. Counts reflect the activity of public catalogues, not how secure anyone is. Weak signals, not an audit.';

const fail = m => { console.error(`pulse-read: ${m}`); process.exit(1); };
const isDate = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s + 'T00:00:00Z'));
const isTime = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(s) && !Number.isNaN(Date.parse(s));
const inRange = s => { const t = Date.parse(s.length === 10 ? s + 'T00:00:00Z' : s); return t >= Date.parse('2020-01-01T00:00:00Z') && t <= Date.now() + 86_400_000; };
const isCount = n => Number.isInteger(n) && n >= 0 && n < 10_000_000;
const counted = n => ({ total: n });
// a calendar day that round-trips (2026-02-30 does not), from 2020 to today UTC
const isDay = s => isDate(s) && new Date(s + 'T00:00:00Z').toISOString().slice(0, 10) === s && s >= '2020-01-01' && s <= new Date().toISOString().slice(0, 10);
// a band map with exactly our six bands, each a whole count, adding up to the total (shared by the 24-hour and daily paths)
const bandsOk = (b, total) => !!b && typeof b === 'object' && !Array.isArray(b) && Object.keys(b).length === BANDS.length && Object.keys(b).every(k => BANDS.includes(k)) && BANDS.every(k => isCount(b[k])) && BANDS.reduce((s, k) => s + b[k], 0) === total; // the real number, however small (Dinis, 18 Nov 2026, about 23:40 UTC)

async function get(name) {
  const i = process.argv.indexOf('--from');
  if (i > 0) return JSON.parse(readFileSync(`${process.argv[i + 1]}/${name === 'kev' ? 'cisa-kev' : 'nvd-cve'}.json`, 'utf8'));
  const res = await fetch(SOURCES[name], { redirect: 'error', signal: AbortSignal.timeout(30_000), headers: { accept: 'application/json' } });
  if (!res.ok) fail(`${name}: HTTP ${res.status}`);
  const reader = res.body.getReader(); const parts = []; let n = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; n += value.length; if (n > MAX_BYTES) fail(`${name}: larger than ${MAX_BYTES} bytes`); parts.push(value); }
  try { return JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { fail(`${name}: not JSON`); }
}

// Monday of the ISO week, as YYYY-MM-DD.
const monday = d => { const t = new Date(d + 'T00:00:00Z'); const wd = (t.getUTCDay() + 6) % 7; t.setUTCDate(t.getUTCDate() - wd); return t.toISOString().slice(0, 10); };
const addDays = (d, k) => { const t = new Date(d + 'T00:00:00Z'); t.setUTCDate(t.getUTCDate() + k); return t.toISOString().slice(0, 10); };
const load = (f, empty) => (existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : empty);
const save = (f, o) => { writeFileSync(f + '.tmp', JSON.stringify(o, null, 2) + '\n'); renameSync(f + '.tmp', f); };

const [kev, nvd] = [await get('kev'), await get('nvd')];

// --- CISA KEV: CVEs added per week, counted by us from each entry's dateAdded. ---
if (!isTime(kev.read_at) || !inRange(kev.read_at)) fail('kev: read_at is not a plausible ISO time');
if (!Array.isArray(kev.vulnerabilities) || kev.vulnerabilities.length === 0) fail('kev: no vulnerabilities list');
const perWeek = new Map();
for (const v of kev.vulnerabilities) {
  if (!v || !isDate(v.dateAdded) || !inRange(v.dateAdded)) fail('kev: an entry has no valid dateAdded');
  const w = monday(v.dateAdded); perWeek.set(w, (perWeek.get(w) || 0) + 1);
}
const readDay = kev.read_at.slice(0, 10);
const thisWeek = monday(readDay);
const weeks = []; // every week from the first to this one, zero-filled
for (let w = [...perWeek.keys()].sort()[0]; w <= thisWeek; w = addDays(w, 7)) weeks.push(w);
const kevHistFile = `${HIST}/kev-weekly.json`;
mkdirSync(HIST, { recursive: true });
const kevHist = load(kevHistFile, { about: 'CVEs added to CISA KEV per week (Monday start), counted by cyber.promptugal.news from each entry\'s dateAdded. Append-only: a completed week never changes; the current week is partial.', points: [] });
const old = new Map(kevHist.points.map(p => [p.week, p]));
const kevPoints = weeks.map(w => {
  const n = perWeek.get(w) || 0; const partial = w === thisWeek;
  const p = old.get(w);
  const f = counted(n);
  if (p && !p.partial && p.total !== f.total) fail(`kev: completed week ${w} changed; not overwriting (a person decides)`);
  return { week: w, partial, ...f, first_read_at: p ? p.first_read_at : kev.read_at, read_at: kev.read_at };
});
for (const w of old.keys()) if (!weeks.includes(w)) fail(`kev: week ${w} is in the history but not in this read; not dropping it (a person decides)`);
kevHist.points = kevPoints;

// --- NVD: one snapshot per read: new CVEs in the 24 hours before the read, by severity band. ---
if (!isTime(nvd.read_at) || !inRange(nvd.read_at)) fail('nvd: read_at is not a plausible ISO time');
const l = nvd.last_24h;
if (!l || !isCount(l.new) || typeof l.new_by_severity !== 'object') fail('nvd: last_24h missing');
if (!bandsOk(l.new_by_severity, l.new)) fail('nvd: the severity bands are unexpected or do not add up to the total');
const nvdHistFile = `${HIST}/nvd-24h.json`;
const nvdHist = load(nvdHistFile, { about: 'New CVEs in NVD in the 24 hours before each read, by CVSS base severity band, as read by data.b@ every 6 hours. Snapshots overlap: never add them up. Append-only.', notice: NVD_NOTICE, points: [] });
const prev = nvdHist.points.find(p => p.read_at === nvd.read_at);
const snap = { read_at: nvd.read_at, window_hours: 24, ...counted(l.new), by_band: Object.fromEntries(BANDS.map(b => [b, counted(l.new_by_severity[b])])) };
if (prev && JSON.stringify(prev) !== JSON.stringify(snap)) fail(`nvd: snapshot ${nvd.read_at} already recorded with other values; not overwriting`);
const lastRead = nvdHist.points.at(-1);
if (!prev && lastRead && nvd.read_at < lastRead.read_at) fail('nvd: this read is older than the last one kept');
if (!prev) nvdHist.points.push(snap);
nvdHist.points.sort((a, b) => a.read_at.localeCompare(b.read_at));

// --- NVD: new CVEs per complete UTC day, from data.b@'s daily_totals (counted by data.b@ from NVD's values). ---
// Only days with complete === true are kept. A kept day never changes; one missing from a read that still covers its date
// stops the run (a person decides); one older than the read's window simply stays in our history (data.b@ keeps 30 days).
// These are UTC-day totals: never mixed with the 24-hour snapshots above.
const MAX_READ_DAYS = 60, MAX_HIST_DAYS = 3700, MAX_DAY = 20_000;
const dt = nvd.daily_totals;
if (dt !== undefined && (dt === null || typeof dt !== 'object' || Array.isArray(dt))) fail('nvd: daily_totals is not an object');
const dayKeys = Object.keys(dt || {});
if (dayKeys.length > MAX_READ_DAYS) fail(`nvd: daily_totals has more than ${MAX_READ_DAYS} days`);
const dayFile = `${HIST}/nvd-daily.json`;
const dayHist = load(dayFile, { about: 'New CVEs in NVD per complete UTC day, by CVSS base severity band, counted by data.b@ from NVD\'s values and kept by cyber.promptugal.news. Append-only: a complete day never changes. UTC-day totals, not the 24-hour snapshots.', notice: NVD_NOTICE, points: [] });
// the kept history is re-checked too: a hand edit that breaks a point stops the run rather than the build (AppSec, 10:25 UTC)
for (const p of dayHist.points) if (!p || !isDay(p.day) || !isCount(p.total) || !p.by_band || !bandsOk(Object.fromEntries(Object.entries(p.by_band).map(([k, v]) => [k, v && v.total])), p.total)) fail('nvd: a point in the kept daily history fails its checks');
const keptDays = new Map(dayHist.points.map(p => [p.day, p]));
const readDays = new Set();
for (const day of dayKeys) {
  if (!isDay(day)) fail(`nvd: daily_totals has a day that is not a real past or present UTC date`);
  const v = Object.getOwnPropertyDescriptor(dt, day).value;
  if (!v || typeof v !== 'object' || v.complete !== true) continue; // the open day, or anything not strictly complete, is not kept
  const dayEnd = Date.parse(day + 'T00:00:00Z') + 86_400_000;
  if (dayEnd > Date.now()) fail(`nvd: day ${day} is marked complete before it has ended`);
  if (!isCount(v.new) || v.new > MAX_DAY) fail(`nvd: day ${day} has no valid total`);
  if (!v.by_severity || !bandsOk(v.by_severity.new, v.new)) fail(`nvd: day ${day}: the bands are unexpected or do not add up`);
  if (!isTime(v.counted_at) || Date.parse(v.counted_at) < dayEnd || Date.parse(v.counted_at) > Date.now() + 600_000) fail(`nvd: day ${day}: counted_at is not between the end of the day and now`);
  readDays.add(day);
  const pt = { day, ...counted(v.new), by_band: Object.fromEntries(BANDS.map(k => [k, counted(v.by_severity.new[k])])), counted_at: v.counted_at };
  const old = keptDays.get(day);
  if (old) { if (old.total !== pt.total || JSON.stringify(old.by_band) !== JSON.stringify(pt.by_band)) fail(`nvd: complete day ${day} changed; not overwriting (a person decides)`); continue; }
  keptDays.set(day, pt);
}
// data.b@ keeps 30 days: any kept day from the last 25 must still be in the read as complete, even if the read is empty
const recent = new Date(Date.now() - 25 * 86_400_000).toISOString().slice(0, 10);
for (const d of keptDays.keys()) if (d >= recent && !readDays.has(d)) fail(`nvd: complete day ${d} is missing from a read that covers it; not dropping it (a person decides)`);
if (keptDays.size > MAX_HIST_DAYS) fail('nvd: daily history is longer than expected');
dayHist.points = [...keptDays.values()].sort((a, b) => a.day.localeCompare(b.day));

// --- The pulse: totals only. ---
const pulse = load(`${DIR}/index.json`, {});
const LIC_OURS = { name: 'CC BY 4.0', url: 'https://creativecommons.org/licenses/by/4.0/', holder: 'PrompTugal.news' };
pulse.state = 'live';
pulse.state_note = 'Worldwide totals from CISA KEV and NVD, read from data.promptugal.news. The Portugal lens (vendors relevant to Portugal) is not built yet.';
pulse.updated = new Date().toISOString().slice(0, 10);
pulse.caveat = CAVEAT;
pulse.series = [
  { id: 'kev-added-weekly', title: 'CVEs added to CISA\'s known-exploited list, per week, worldwide', source: 'CISA Known Exploited Vulnerabilities (CC0), via https://data.promptugal.news/api/v1/cisa-kev/latest.json (CC BY 4.0, PrompTugal.news)',
    source_license: { name: 'CC0 1.0', url: 'https://raw.githubusercontent.com/cisagov/kev-data/develop/LICENSE' }, license: LIC_OURS, read_at: kev.read_at,
    points: kevPoints.map(p => ({ week: p.week, partial: p.partial, total: p.total, read_at: p.read_at })) },
  { id: 'nvd-new-24h', title: 'New CVEs in NVD in the 24 hours before each read, worldwide, by severity band', source: 'NVD CVE API 2.0, via https://data.promptugal.news/api/v1/nvd-cve/latest.json (CC BY 4.0, PrompTugal.news). The totals are ours, counted from NVD\'s values.',
    source_license: { name: 'NIST copyright notice', url: 'https://www.nist.gov/oism/copyrights' }, notice: NVD_NOTICE, license: LIC_OURS, read_at: nvd.read_at,
    points: nvdHist.points },
  { id: 'nvd-new-daily', title: 'New CVEs in NVD per complete UTC day, worldwide, by severity band', source: 'NVD CVE API 2.0, counted per UTC day by data.b@, via https://data.promptugal.news/api/v1/nvd-cve/latest.json (CC BY 4.0, PrompTugal.news). The totals are counted from NVD\'s values.',
    source_license: { name: 'NIST copyright notice', url: 'https://www.nist.gov/oism/copyrights' }, notice: NVD_NOTICE, license: LIC_OURS, read_at: nvd.read_at,
    points: dayHist.points.map(p => ({ day: p.day, total: p.total, by_band: p.by_band })) },
];

// The limits, checked in code before anything is written: every string must be one of ours or an ISO date/time.
const ALLOWED = new Set(['https://creativecommons.org/licenses/by/4.0/', 'https://raw.githubusercontent.com/cisagov/kev-data/develop/LICENSE', 'https://www.nist.gov/oism/copyrights']);
const IP = /\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b/i;
const HOST = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i;
const OUR_URLS = [SOURCES.kev, SOURCES.nvd, "data.promptugal.news", "PrompTugal.news"]; // the only URLs allowed inside free text: our own fixed sources
const stripOurs = x => OUR_URLS.reduce((t, u) => t.split(u).join(' '), x);
(function walk(x, path) {
  if (typeof x === 'number') { if (!Number.isInteger(x) || x < 0) fail(`limit: ${path} is not a whole count`); return; }
  if (typeof x === 'string') {
    if (ALLOWED.has(x) || isDate(x) || isTime(x)) return;
    const rest = stripOurs(x);
    if (IP.test(rest)) fail(`limit: ${path} looks like an IP address`);
    if (HOST.test(rest.replace(/\b\d+(\.\d+)+\b/g, ''))) fail(`limit: ${path} looks like a host name`);
    return;
  }
  if (Array.isArray(x)) return x.forEach((y, i) => walk(y, `${path}[${i}]`));
  if (x && typeof x === 'object') for (const [k, v] of Object.entries(x)) walk(v, `${path}.${k}`);
})({ series: pulse.series, state_note: pulse.state_note, caveat: pulse.caveat, kevHist: kevHist.points, nvdHist: nvdHist.points, dayHist: dayHist.points }, 'pulse');

save(kevHistFile, kevHist);
save(nvdHistFile, nvdHist);
save(dayFile, dayHist);
save(`${DIR}/index.json`, pulse);
const last = kevPoints.at(-1);
console.log(`pulse: ${kevPoints.length} KEV weeks (this week ${last.week}, partial, ${last.total}), ${nvdHist.points.length} NVD snapshot(s), ${dayHist.points.length} complete NVD day(s); KEV read ${kev.read_at}, NVD read ${nvd.read_at}`);
