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
  euvd: 'https://data.promptugal.news/api/v1/euvd/latest.json',
};
const MAX_BYTES = 20 * 1024 * 1024;
const BANDS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'unscored'];
const DIR = 'src/api/v1/pulse';
const HIST = `${DIR}/history`;
// The one credit ENISA's legal notice asks for, kept exact: the limits walk below allows this string and no other with a host in it.
const EUVD_CREDIT = 'Source: ENISA, EU Vulnerability Database (euvd.enisa.europa.eu)';
const EUVD_MAX = 4 * 1024 * 1024;
const NVD_NOTICE = 'This product uses the NVD API but is not endorsed or certified by the NVD.';
const CAVEAT = 'Worldwide totals. Counts reflect the activity of public catalogues, not how secure anyone is. Weak signals, not an audit.';

const fail = m => { console.error(`pulse-read: ${m}`); process.exit(1); };
const isDate = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s + 'T00:00:00Z'));
const isTime = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(s) && !Number.isNaN(Date.parse(s));
const inRange = s => { const t = Date.parse(s.length === 10 ? s + 'T00:00:00Z' : s); return t >= Date.parse('2020-01-01T00:00:00Z') && t <= Date.now() + 86_400_000; };
const isCount = n => Number.isInteger(n) && n >= 0 && n < 10_000_000;
const counted = n => ({ total: n }); // the real number, however small (Dinis, 18 Nov 2026, about 23:40 UTC)
// a calendar day that round-trips (2026-02-30 does not), from 2020 to today UTC
const isDay = s => isDate(s) && new Date(s + 'T00:00:00Z').toISOString().slice(0, 10) === s && s >= '2020-01-01' && s <= new Date().toISOString().slice(0, 10);
// a band map with exactly our six bands, each a whole count, adding up to the total (shared by the 24-hour and daily paths)
const bandsOk = (b, total) => !!b && typeof b === 'object' && !Array.isArray(b) && Object.keys(b).length === BANDS.length && Object.keys(b).every(k => BANDS.includes(k)) && BANDS.every(k => isCount(b[k])) && BANDS.reduce((s, k) => s + b[k], 0) === total;

async function get(name) {
  const i = process.argv.indexOf('--from');
  if (i > 0) { const f = `${process.argv[i + 1]}/${{ kev: 'cisa-kev', nvd: 'nvd-cve', euvd: 'euvd' }[name]}.json`; if (name === 'euvd' && !existsSync(f)) return null; return JSON.parse(readFileSync(f, 'utf8')); }
  const cap = name === 'euvd' ? EUVD_MAX : MAX_BYTES;
  // EUVD is optional: if it cannot be fetched, KEV and NVD still update and the EU view keeps its last kept figures
  const soft = m => { if (name === 'euvd') { console.warn(`pulse-read: WARNING euvd skipped: ${m}`); return true; } fail(`${name}: ${m}`); };
  let res; try { res = await fetch(SOURCES[name], { redirect: 'error', signal: AbortSignal.timeout(30_000), headers: { accept: 'application/json' } }); } catch (e) { if (soft(`fetch failed (${String(e && e.name)})`)) return null; }
  if (!res.ok && soft(`HTTP ${res.status}`)) return null;
  const reader = res.body.getReader(); const parts = []; let n = 0;
  for (;;) { const { done, value } = await reader.read(); if (done) break; n += value.length; if (n > cap) { reader.cancel().catch(() => {}); if (soft(`larger than ${cap} bytes`)) return null; } parts.push(value); }
  try { return JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { if (soft('not JSON')) return null; }
}

// Monday of the ISO week, as YYYY-MM-DD.
const monday = d => { const t = new Date(d + 'T00:00:00Z'); const wd = (t.getUTCDay() + 6) % 7; t.setUTCDate(t.getUTCDate() - wd); return t.toISOString().slice(0, 10); };
const addDays = (d, k) => { const t = new Date(d + 'T00:00:00Z'); t.setUTCDate(t.getUTCDate() + k); return t.toISOString().slice(0, 10); };
const load = (f, empty) => (existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : empty);
const save = (f, o) => { writeFileSync(f + '.tmp', JSON.stringify(o, null, 2) + '\n'); renameSync(f + '.tmp', f); };

// EUVD is paused (19 Nov 2026, about 13:37 UTC): rights@ has not cleared it (finding R10; ENISA's legal notice cannot be
// quoted by machine and a person must read it). Not fetched, not kept, not shown until rights@ and Dinis clear it.
const EUVD_ON = process.argv.includes('--from') && process.env.PULSE_TEST_EUVD === '1'; // only the tests, on crafted files, ever turn it on
const [kev, nvd, euvd] = [await get('kev'), await get('nvd'), EUVD_ON ? await get('euvd') : null];

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

// --- Complete UTC days, one function for both NVD and EUVD (data.b@'s daily_totals, counted by data.b@ from each source's
// values). Only days with complete === true are kept. A kept day never changes; a kept day from the last 25 days that is
// missing from a read stops the run (a person decides); one older than that simply stays in our history (NVD keeps 30
// days; EUVD about 3, so its window is 1 day). These are UTC-day totals: never mixed with the 24-hour snapshots, and never added across sources.
const MAX_READ_DAYS = 60, MAX_HIST_DAYS = 3700, MAX_DAY = 20_000;
function keepDays(label, dt, file, about, window = 25) {
  if (dt !== undefined && (dt === null || typeof dt !== 'object' || Array.isArray(dt))) fail(`${label}: daily_totals is not an object`);
  const dayKeys = Object.keys(dt || {});
  if (dayKeys.length > MAX_READ_DAYS) fail(`${label}: daily_totals has more than ${MAX_READ_DAYS} days`);
  const hist = load(file, { about, points: [] });
  // the kept history is re-checked too: a hand edit that breaks a point stops the run rather than the build
  for (const p of hist.points) if (!p || !isDay(p.day) || !isCount(p.total) || !p.by_band || !bandsOk(Object.fromEntries(Object.entries(p.by_band).map(([k, v]) => [k, v && v.total])), p.total)) fail(`${label}: a point in the kept daily history fails its checks`);
  const kept = new Map(hist.points.map(p => [p.day, p]));
  const readDays = new Set();
  for (const day of dayKeys) {
    if (!isDay(day)) fail(`${label}: daily_totals has a day that is not a real past or present UTC date`);
    const v = Object.getOwnPropertyDescriptor(dt, day).value;
    if (!v || typeof v !== 'object' || v.complete !== true) continue; // the open day, or anything not strictly complete, is not kept
    const dayEnd = Date.parse(day + 'T00:00:00Z') + 86_400_000;
    if (dayEnd > Date.now()) fail(`${label}: day ${day} is marked complete before it has ended`);
    if (!isCount(v.new) || v.new > MAX_DAY) fail(`${label}: day ${day} has no valid total`);
    if (!v.by_severity || !bandsOk(v.by_severity.new, v.new)) fail(`${label}: day ${day}: the bands are unexpected or do not add up`);
    if (!isTime(v.counted_at) || Date.parse(v.counted_at) < dayEnd || Date.parse(v.counted_at) > Date.now() + 600_000) fail(`${label}: day ${day}: counted_at is not between the end of the day and now`);
    readDays.add(day);
    const pt = { day, ...counted(v.new), by_band: Object.fromEntries(BANDS.map(k => [k, counted(v.by_severity.new[k])])), counted_at: v.counted_at };
    const old = kept.get(day);
    if (old) { if (old.total !== pt.total || JSON.stringify(old.by_band) !== JSON.stringify(pt.by_band)) fail(`${label}: complete day ${day} changed; not overwriting (a person decides)`); continue; }
    kept.set(day, pt);
  }
  const recent = new Date(Date.now() - window * 86_400_000).toISOString().slice(0, 10); // the source keeps at least this many days
  for (const d of kept.keys()) if (d >= recent && !readDays.has(d)) fail(`${label}: complete day ${d} is missing from a read that covers it; not dropping it (a person decides)`);
  if (kept.size > MAX_HIST_DAYS) fail(`${label}: daily history is longer than expected`);
  hist.points = [...kept.values()].sort((a, b) => a.day.localeCompare(b.day));
  return hist;
}
const dayFile = `${HIST}/nvd-daily.json`;
const dayHist = keepDays('nvd', nvd.daily_totals, dayFile, 'New CVEs in NVD per complete UTC day, by CVSS base severity band, counted by data.b@ from NVD\'s values and kept by PrompTugal.news Cyber. Append-only: a complete day never changes. UTC-day totals, not the 24-hour snapshots.');
dayHist.notice = NVD_NOTICE;

// --- EUVD (ENISA's EU Vulnerability Database), the EU view: aggregates only. No record, vendor, link or EUVD id is kept.
// Its CVE ids overlap NVD's and are not de-duplicated: EUVD and NVD figures are never added together.
let euvdHist = null, euvdDays = null, euvdSnap = null;
const euvdFile = `${HIST}/euvd-24h.json`, euvdDayFile = `${HIST}/euvd-daily.json`;
if (euvd) {
  if (euvd.source !== 'euvd' || !euvd.schema || euvd.schema.version !== 'v1') fail('euvd: not the euvd v1 file');
  if (!isTime(euvd.read_at) || !inRange(euvd.read_at) || Date.parse(euvd.read_at) > Date.now() + 600_000) fail('euvd: read_at is not a plausible ISO time');
  const e = euvd.last_24h, c = euvd.counts;
  if (!e || typeof e !== 'object' || !isCount(e.new) || e.new > 100_000 || !bandsOk(e.new_by_severity, e.new)) fail('euvd: last_24h is missing, or its bands do not add up');
  if (!c || typeof c !== 'object' || !isCount(c.in_last_24h) || !isCount(c.exploited_in_last_24h) || !isCount(c.exploited_total_euvd)) fail('euvd: counts are missing');
  if (!isCount(e.exploited) || e.exploited !== c.exploited_in_last_24h || e.exploited > c.in_last_24h || e.new > c.in_last_24h) fail('euvd: the 24-hour exploited count is not consistent');
  if (c.exploited_total_euvd < c.exploited_in_last_24h || c.exploited_total_euvd > 100_000) fail('euvd: the exploited total is out of bounds');
  euvdHist = load(euvdFile, { about: 'EUVD (ENISA): vulnerabilities new in the 24 hours before each read, by severity band, and the count EUVD lists as exploited, as read by data.b@ every 6 hours. Snapshots overlap: never add them up. Never added to NVD figures. Append-only.', credit: EUVD_CREDIT, points: [] });
  for (const p of euvdHist.points) if (!p || !isTime(p.read_at) || !isCount(p.total) || !p.by_band || !bandsOk(Object.fromEntries(Object.entries(p.by_band).map(([k, v]) => [k, v && v.total])), p.total) || !isCount(p.exploited_24h) || !isCount(p.exploited_total)) fail('euvd: a point in the kept 24-hour history fails its checks');
  if (euvdHist.points.length > 20_000) fail('euvd: 24-hour history is longer than expected');
  euvdSnap = { read_at: euvd.read_at, window_hours: 24, ...counted(e.new), by_band: Object.fromEntries(BANDS.map(b => [b, counted(e.new_by_severity[b])])), exploited_24h: e.exploited, exploited_total: c.exploited_total_euvd };
  const prevE = euvdHist.points.find(p => Date.parse(p.read_at) === Date.parse(euvd.read_at)), lastE = euvdHist.points.at(-1);
  if (prevE && JSON.stringify(prevE) !== JSON.stringify(euvdSnap)) fail(`euvd: snapshot ${euvd.read_at} already recorded with other values; not overwriting`);
  if (!prevE && lastE && Date.parse(euvd.read_at) < Date.parse(lastE.read_at)) fail('euvd: this read is older than the last one kept');
  // a running total: it may move a little as EUVD revises, but a large fall is a person's decision
  const maxE = Math.max(0, ...euvdHist.points.map(p => p.exploited_total));
  if (!prevE && lastE && euvdSnap.exploited_total < maxE * 0.98) fail('euvd: the exploited total is more than 2% below the highest kept; a person decides');
  if (!prevE && lastE && euvdSnap.exploited_total > lastE.exploited_total * 1.5 + 50) fail('euvd: the exploited total rose by more than half since the last read; a person decides');
  if (!prevE) euvdHist.points.push(euvdSnap);
  euvdHist.points.sort((a, b) => a.read_at.localeCompare(b.read_at));
  euvdDays = keepDays('euvd', euvd.daily_totals, euvdDayFile, 'EUVD (ENISA): vulnerabilities new per complete UTC day, by severity band, counted by data.b@ from EUVD\'s values and kept by PrompTugal.news Cyber. Append-only. Never added to NVD figures.', 1); // EUVD's daily_totals covers about 3 days: only yesterday must still be present
  euvdDays.credit = EUVD_CREDIT;
}

// --- The pulse: totals only. ---
const pulse = load(`${DIR}/index.json`, {});
const LIC_OURS = { name: 'CC BY 4.0', url: 'https://creativecommons.org/licenses/by/4.0/', holder: 'PrompTugal.news' };
pulse.state = 'live';
pulse.state_note = 'Worldwide totals from CISA KEV and NVD, and the EU view from ENISA EUVD (never added to NVD), read from data.promptugal.news. The Portugal lens (vendors relevant to Portugal) is not built yet.';
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
  ...(euvdHist ? [
    { id: 'euvd-24h', title: 'EU view (ENISA EUVD): vulnerabilities new in the 24 hours before each read, by severity band, and those EUVD lists as exploited', source: 'ENISA EUVD, via https://data.promptugal.news/api/v1/euvd/latest.json (CC BY 4.0, PrompTugal.news). Severity bands are from the CVSS base score by the standard ranges. Never added to the NVD figures: the two databases overlap.',
      credit: EUVD_CREDIT, source_license: { name: 'ENISA legal notice (reproduction authorised with the source acknowledged)', url: 'https://www.enisa.europa.eu/about-enisa/legal-notice' }, license: LIC_OURS, read_at: euvd.read_at,
      points: euvdHist.points },
    { id: 'euvd-new-daily', title: 'EU view (ENISA EUVD): vulnerabilities new per complete UTC day, by severity band', source: 'ENISA EUVD, counted per UTC day by data.b@, via https://data.promptugal.news/api/v1/euvd/latest.json (CC BY 4.0, PrompTugal.news). Never added to the NVD figures.',
      credit: EUVD_CREDIT, source_license: { name: 'ENISA legal notice (reproduction authorised with the source acknowledged)', url: 'https://www.enisa.europa.eu/about-enisa/legal-notice' }, license: LIC_OURS, read_at: euvd.read_at,
      points: euvdDays.points.map(p => ({ day: p.day, total: p.total, by_band: p.by_band })) },
  ] : []),
];

// The limits, checked in code before anything is written: every string must be one of ours or an ISO date/time.
const ALLOWED = new Set(['https://creativecommons.org/licenses/by/4.0/', 'https://raw.githubusercontent.com/cisagov/kev-data/develop/LICENSE', 'https://www.nist.gov/oism/copyrights', 'https://www.enisa.europa.eu/about-enisa/legal-notice']);
// exact strings only: the EUVD credit names ENISA's host because ENISA's notice asks for the source to be acknowledged
const CREDITS = new Set([EUVD_CREDIT]);
const IP = /\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b/i;
const HOST = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i;
const OUR_URLS = [SOURCES.kev, SOURCES.nvd, SOURCES.euvd, "data.promptugal.news", "PrompTugal.news"]; // the only URLs allowed inside free text: our own fixed sources
const stripOurs = x => OUR_URLS.reduce((t, u) => t.split(u).join(' '), x);
(function walk(x, path) {
  if (typeof x === 'number') { if (!Number.isInteger(x) || x < 0) fail(`limit: ${path} is not a whole count`); return; }
  if (typeof x === 'string') {
    if (ALLOWED.has(x) || CREDITS.has(x) || isDate(x) || isTime(x)) return;
    const rest = stripOurs(x);
    if (IP.test(rest)) fail(`limit: ${path} looks like an IP address`);
    if (HOST.test(rest.replace(/\b\d+(\.\d+)+\b/g, ''))) fail(`limit: ${path} looks like a host name`);
    return;
  }
  if (Array.isArray(x)) return x.forEach((y, i) => walk(y, `${path}[${i}]`));
  if (x && typeof x === 'object') for (const [k, v] of Object.entries(x)) walk(v, `${path}.${k}`);
})({ series: pulse.series, state_note: pulse.state_note, caveat: pulse.caveat, kevHist: kevHist.points, nvdHist: nvdHist.points, dayHist: dayHist.points, euvdHist: euvdHist, euvdDays: euvdDays }, 'pulse');

save(kevHistFile, kevHist);
save(nvdHistFile, nvdHist);
save(dayFile, dayHist);
if (euvdHist) { save(euvdFile, euvdHist); save(euvdDayFile, euvdDays); }
save(`${DIR}/index.json`, pulse);
const last = kevPoints.at(-1);
console.log(`pulse: ${kevPoints.length} KEV weeks (this week ${last.week}, partial, ${last.total}), ${nvdHist.points.length} NVD snapshot(s), ${dayHist.points.length} complete NVD day(s), ${euvdHist ? `${euvdHist.points.length} EUVD snapshot(s) and ${euvdDays.points.length} complete EUVD day(s)` : 'no EUVD file'}; KEV read ${kev.read_at}, NVD read ${nvd.read_at}`);
