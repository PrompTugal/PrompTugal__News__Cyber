// Data in the browser (Dinis, 19 November 2026, about 01:13 UTC: "yes, option 1, load the data in the browser";
// PrompTugal__News__Website board/guidance/2026-11-19-load-the-data-in-the-browser.md). cyber.b@PrompTugal.dinis.
// When the home page opens, and every 10 minutes after, read the latest KEV and NVD files from data.promptugal.news
// (our own host; no cookie, no referrer) and redraw the pulse from them. The figures built into the page stay unless a
// file passes every check: the expected shape, a read time newer than the one shown, values in bounds. Every value is
// written with textContent or as SVG attributes computed from numbers. Nothing is stored or sent.
'use strict';
(() => {
  const SRC = { kev: 'https://data.promptugal.news/api/v1/cisa-kev/latest.json', nvd: 'https://data.promptugal.news/api/v1/nvd-cve/latest.json' };
  const STALE_MS = 12 * 3600 * 1000; // both files are read every 6 hours: older than 12 hours is stale
  const BANDS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'unscored'];
  const SVGNS = 'http://www.w3.org/2000/svg';
  const $ = id => document.getElementById(id);
  const isTime = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(s) && !Number.isNaN(Date.parse(s)) && Date.parse(s) <= Date.now() + 10 * 60 * 1000; // never from the future
  const isDate = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s);
  const isCount = n => Number.isInteger(n) && n >= 0 && n < 1e7;
  const fmt = t => t.replace('T', ' ').replace(/:\d\d(\.\d+)?Z$/, ' UTC');
  const ago = t => Date.now() - Date.parse(t);
  const el = (tag, text) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = String(text); return e; };
  const sv = (tag, attrs, text) => { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v)); if (text !== undefined) e.textContent = String(text); return e; };
  const monday = d => { const t = new Date(d + 'T00:00:00Z'); t.setUTCDate(t.getUTCDate() - ((t.getUTCDay() + 6) % 7)); return t.toISOString().slice(0, 10); };
  const addDays = (d, k) => { const t = new Date(d + 'T00:00:00Z'); t.setUTCDate(t.getUTCDate() + k); return t.toISOString().slice(0, 10); };

  async function get(u) {
    const r = await fetch(u, { credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-cache', headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  }
  function mark(id, readAt) { const s = $(id); if (s) s.textContent = ago(readAt) > STALE_MS ? '(stale: older than 12 hours)' : ''; }

  function kev(d) {
    const svg = $('p-kev-svg'); if (!svg) return;
    if (!d || !isTime(d.read_at) || !Array.isArray(d.vulnerabilities) || d.vulnerabilities.length < 100) throw new Error('KEV file: unexpected shape');
    if (Date.parse(d.read_at) <= Date.parse(svg.dataset.read || '1970-01-01T00:00:00Z')) { mark('p-kev-state', svg.dataset.read); return 'kept'; }
    const per = new Map();
    for (const v of d.vulnerabilities) { if (!v || !isDate(v.dateAdded)) throw new Error('KEV file: a bad date'); const w = monday(v.dateAdded); per.set(w, (per.get(w) || 0) + 1); }
    const now = monday(d.read_at.slice(0, 10)); const weeks = []; for (let i = 11; i >= 0; i--) weeks.push(addDays(now, -7 * i));
    const pts = weeks.map(w => ({ week: w, total: per.get(w) || 0, partial: w === now }));
    if (pts.some(p => p.total > 1000)) throw new Error('KEV file: a week out of bounds');
    const W = 720, H = 220, bw = W / pts.length, max = Math.max(5, ...pts.map(p => p.total));
    const kids = [];
    pts.forEach((p, i) => {
      const x = i * bw + 6, w = bw - 12, bh = Math.max(2, Math.round((p.total / max) * (H - 50)));
      kids.push(sv('rect', { class: p.partial ? 'b-part' : 'b', x, y: H - 30 - bh, width: w, height: bh }));
      kids.push(sv('text', { class: 'v', x: x + w / 2, y: H - 36 - bh, 'text-anchor': 'middle' }, p.total));
      kids.push(sv('text', { class: 'w', x: x + w / 2, y: H - 12, 'text-anchor': 'middle' }, p.week.slice(5)));
    });
    svg.replaceChildren(...kids);
    svg.setAttribute('aria-label', 'CVEs added to CISA\'s known-exploited list, per week, worldwide: ' + pts.map(p => `${p.week} ${p.total}`).join('; '));
    svg.dataset.read = d.read_at;
    const t = $('p-kev-table');
    if (t) { const head = t.rows[0]; const rows = pts.slice().reverse().map(p => { const tr = el('tr'); tr.append(el('td', p.week + (p.partial ? ' (so far)' : '')), el('td', p.total)); return tr; }); t.replaceChildren(head, ...rows); }
    $('p-kev-read').textContent = fmt(d.read_at); mark('p-kev-state', d.read_at);
    return 'live';
  }

  function nvd(d) {
    const r = $('p-nvd-read'); if (!r) return;
    const l = d && d.last_24h;
    if (!d || !isTime(d.read_at) || !l || !isCount(l.new) || typeof l.new_by_severity !== 'object') throw new Error('NVD file: unexpected shape');
    if (Object.keys(l.new_by_severity).some(k => !BANDS.includes(k)) || BANDS.some(b => !isCount(l.new_by_severity[b]))) throw new Error('NVD file: unexpected bands');
    if (BANDS.reduce((s, b) => s + l.new_by_severity[b], 0) !== l.new) throw new Error('NVD file: bands do not add up');
    if (Date.parse(d.read_at) <= Date.parse(r.dataset.read || '1970-01-01T00:00:00Z')) { mark('p-nvd-state', r.dataset.read); return 'kept'; }
    $('p-nvd-total').textContent = String(l.new);
    const t = $('p-nvd-table');
    if (t) { const head = t.rows[0]; const rows = BANDS.map(b => { const tr = el('tr'); tr.append(el('td', b === 'unscored' ? 'not scored yet' : b.toLowerCase()), el('td', l.new_by_severity[b])); return tr; }); t.replaceChildren(head, ...rows); }
    r.textContent = fmt(d.read_at); r.dataset.read = d.read_at; mark('p-nvd-state', d.read_at);
    return 'live';
  }

  async function refresh() {
    const out = [];
    for (const [name, fn, u] of [['KEV', kev, SRC.kev], ['NVD', nvd, SRC.nvd]]) {
      try { const r = fn(await get(u)); out.push(`${name}: ${r === 'live' ? 'the latest file' : 'the built copy is already the latest'}`); }
      catch (e) { out.push(`${name}: the built copy (the latest file did not pass its checks or could not be read)`); const [id, src] = name === 'KEV' ? ['p-kev-state', $('p-kev-svg')] : ['p-nvd-state', $('p-nvd-read')]; if (src && src.dataset.read) mark(id, src.dataset.read); }
    }
    const s = $('p-live'); if (s) s.textContent = `Figures shown: ${out.join('; ')}. Checked ${new Date().toISOString().slice(11, 16)} UTC, from data.promptugal.news.`;
  }
  refresh();
  setInterval(refresh, 10 * 60 * 1000);
})();
