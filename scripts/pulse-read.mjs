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
const FLOOR = 5; // a total under 5 is never shown on its own (published on /how/)
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
const floored = n => (n >= FLOOR ? { total: n, fewer_than_5: false } : { total: null, fewer_than_5: true });

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
const kevHist = load(kevHistFile, { about: 'CVEs added to CISA KEV per week (Monday start), counted by cyber.promptugal.news from each entry\'s dateAdded; a total under 5 is kept as null with fewer_than_5. Append-only: a completed week never changes; the current week is partial.', points: [] });
const old = new Map(kevHist.points.map(p => [p.week, p]));
const kevPoints = weeks.map(w => {
  const n = perWeek.get(w) || 0; const partial = w === thisWeek;
  const p = old.get(w);
  const f = floored(n);
  if (p && !p.partial && (p.total !== f.total || p.fewer_than_5 !== f.fewer_than_5)) fail(`kev: completed week ${w} changed; not overwriting (a person decides)`);
  return { week: w, partial, ...f, first_read_at: p ? p.first_read_at : kev.read_at, read_at: kev.read_at };
});
for (const w of old.keys()) if (!weeks.includes(w)) fail(`kev: week ${w} is in the history but not in this read; not dropping it (a person decides)`);
kevHist.points = kevPoints;

// --- NVD: one snapshot per read: new CVEs in the 24 hours before the read, by severity band. ---
if (!isTime(nvd.read_at) || !inRange(nvd.read_at)) fail('nvd: read_at is not a plausible ISO time');
const l = nvd.last_24h;
if (!l || !isCount(l.new) || typeof l.new_by_severity !== 'object') fail('nvd: last_24h missing');
const keys = Object.keys(l.new_by_severity);
if (keys.some(k => !BANDS.includes(k)) || BANDS.some(b => !isCount(l.new_by_severity[b]))) fail('nvd: unexpected severity bands');
const bandSum = BANDS.reduce((s, b) => s + l.new_by_severity[b], 0);
if (bandSum !== l.new) fail(`nvd: bands add up to ${bandSum}, not ${l.new}`);
const nvdHistFile = `${HIST}/nvd-24h.json`;
const nvdHist = load(nvdHistFile, { about: 'New CVEs in NVD in the 24 hours before each read, by CVSS base severity band, as read by data.b@ every 6 hours; a total under 5 is kept as null with fewer_than_5. Snapshots overlap: never add them up. Append-only.', notice: NVD_NOTICE, points: [] });
const prev = nvdHist.points.find(p => p.read_at === nvd.read_at);
const snap = { read_at: nvd.read_at, window_hours: 24, ...floored(l.new), by_band: Object.fromEntries(BANDS.map(b => [b, floored(l.new_by_severity[b])])) };
if (prev && JSON.stringify(prev) !== JSON.stringify(snap)) fail(`nvd: snapshot ${nvd.read_at} already recorded with other values; not overwriting`);
const lastRead = nvdHist.points.at(-1);
if (!prev && lastRead && nvd.read_at < lastRead.read_at) fail('nvd: this read is older than the last one kept');
if (!prev) nvdHist.points.push(snap);
nvdHist.points.sort((a, b) => a.read_at.localeCompare(b.read_at));

// --- The pulse: floored totals only. ---
const pulse = load(`${DIR}/index.json`, {});
const LIC_OURS = { name: 'CC BY 4.0', url: 'https://creativecommons.org/licenses/by/4.0/', holder: 'PrompTugal.news' };
pulse.state = 'live';
pulse.state_note = 'Worldwide totals from CISA KEV and NVD, read from data.promptugal.news. The Portugal lens (vendors relevant to Portugal) is not built yet.';
pulse.updated = new Date().toISOString().slice(0, 10);
pulse.caveat = CAVEAT;
pulse.series = [
  { id: 'kev-added-weekly', title: 'CVEs added to CISA\'s known-exploited list, per week, worldwide', source: 'CISA Known Exploited Vulnerabilities (CC0), via https://data.promptugal.news/api/v1/cisa-kev/latest.json (CC BY 4.0, PrompTugal.news)',
    source_license: { name: 'CC0 1.0', url: 'https://raw.githubusercontent.com/cisagov/kev-data/develop/LICENSE' }, license: LIC_OURS, read_at: kev.read_at,
    points: kevPoints.map(p => ({ week: p.week, partial: p.partial, total: p.total, fewer_than_5: p.fewer_than_5, read_at: p.read_at })) },
  { id: 'nvd-new-24h', title: 'New CVEs in NVD in the 24 hours before each read, worldwide, by severity band', source: 'NVD CVE API 2.0, via https://data.promptugal.news/api/v1/nvd-cve/latest.json (CC BY 4.0, PrompTugal.news). The totals are ours, counted from NVD\'s values.',
    source_license: { name: 'NIST copyright notice', url: 'https://www.nist.gov/oism/copyrights' }, notice: NVD_NOTICE, license: LIC_OURS, read_at: nvd.read_at,
    points: nvdHist.points },
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
})({ series: pulse.series, state_note: pulse.state_note, caveat: pulse.caveat, kevHist: kevHist.points, nvdHist: nvdHist.points }, 'pulse');
const under = x => x && typeof x === 'object' && (('total' in x && x.total !== null && x.total < FLOOR) || Object.values(x).some(under));
if (under(pulse.series) || under(kevHist.points) || under(nvdHist.points)) fail('limit: a total under 5');

save(kevHistFile, kevHist);
save(nvdHistFile, nvdHist);
save(`${DIR}/index.json`, pulse);
const last = kevPoints.at(-1);
console.log(`pulse: ${kevPoints.length} KEV weeks (this week ${last.week}, partial, ${last.fewer_than_5 ? 'fewer than 5' : last.total}), ${nvdHist.points.length} NVD snapshot(s); KEV read ${kev.read_at}, NVD read ${nvd.read_at}`);
