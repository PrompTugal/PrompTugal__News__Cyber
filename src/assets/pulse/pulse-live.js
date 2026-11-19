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
  // a link into the explorer; the query is built from our own fixed keys and checked dates or bands only
  const go = (tab, k, v) => `/explore/#${new URLSearchParams({ tab, [k]: v }).toString()}`;
  const a = (href, text) => { const e = el('a', text); e.setAttribute('href', href); return e; };
  const td = node => { const e = el('td'); e.append(node); return e; };
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
      const g = sv('a', { class: 'x-click', href: go('kev', 'week', p.week) });
      g.append(sv('title', {}, `Week of ${p.week}: ${p.total} CVEs. Click to see them.`), sv('rect', { class: 'x-hit', x: i * bw, y: 0, width: bw, height: H }));
      g.append(sv('rect', { class: p.partial ? 'b-part' : 'b', x, y: H - 30 - bh, width: w, height: bh }));
      g.append(sv('text', { class: 'v', x: x + w / 2, y: H - 36 - bh, 'text-anchor': 'middle' }, p.total));
      g.append(sv('text', { class: 'w', x: x + w / 2, y: H - 12, 'text-anchor': 'middle' }, p.week.slice(5)));
      kids.push(g);
    });
    svg.replaceChildren(...kids);
    svg.setAttribute('aria-label', 'CVEs added to CISA\'s known-exploited list, per week, worldwide: ' + pts.map(p => `${p.week} ${p.total}`).join('; '));
    svg.dataset.read = d.read_at;
    const t = $('p-kev-table');
    if (t) { const head = t.rows[0]; const rows = pts.slice().reverse().map(p => { const tr = el('tr'); const c = td(a(go('kev', 'week', p.week), p.week)); if (p.partial) c.append(' (so far)'); tr.append(c, td(a(go('kev', 'week', p.week), p.total))); return tr; }); t.replaceChildren(head, ...rows); }
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
    if (t) { const head = t.rows[0]; const rows = BANDS.map(b => { const tr = el('tr'); tr.append(td(a(go('nvd', 'sev', b), b === 'unscored' ? 'not scored yet' : b.toLowerCase())), el('td', l.new_by_severity[b])); return tr; }); t.replaceChildren(head, ...rows); }
    r.textContent = fmt(d.read_at); r.dataset.read = d.read_at; mark('p-nvd-state', d.read_at);
    return 'live';
  }

  // Complete UTC days: our own kept history (this site) plus any newer complete day in the live NVD file, with the reader's
  // checks: a real past day, complete === true, ended before now, six bands that add up, at most 60 days in the file.
  const isDay = s => isDate(s) && new Date(s + 'T00:00:00Z').toISOString().slice(0, 10) === s && s >= '2020-01-01';
  const bandsOk = (b, t) => !!b && typeof b === 'object' && Object.keys(b).length === BANDS.length && BANDS.every(k => isCount(b[k])) && BANDS.reduce((x, k) => x + b[k], 0) === t;
  const DAYB = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'unscored'];
  async function days(liveNvd) {
    const svg = $('p-day-svg'); if (!svg) return 'none';
    const hist = await get('/api/v1/pulse/history/nvd-daily.json');
    const m = new Map();
    for (const p of (hist && Array.isArray(hist.points) ? hist.points : [])) if (p && isDay(p.day) && isCount(p.total) && p.by_band) m.set(p.day, { day: p.day, total: p.total, b: Object.fromEntries(DAYB.map(k => [k, p.by_band[k] && p.by_band[k].total])) });
    const dt = liveNvd && liveNvd.daily_totals;
    if (dt && typeof dt === 'object' && !Array.isArray(dt) && Object.keys(dt).length <= 60) {
      for (const k of Object.keys(dt)) {
        const v = Object.getOwnPropertyDescriptor(dt, k).value;
        if (!isDay(k) || !v || v.complete !== true || Date.parse(k + 'T00:00:00Z') + 86400000 > Date.now()) continue;
        if (!isCount(v.new) || v.new > 20000 || !v.by_severity || !bandsOk(v.by_severity.new, v.new)) continue;
        if (!isTime(v.counted_at) || Date.parse(v.counted_at) < Date.parse(k + 'T00:00:00Z') + 86400000) continue;
        if (!m.has(k)) m.set(k, { day: k, total: v.new, b: v.by_severity.new });
      }
    }
    const pts = [...m.values()].filter(p => DAYB.every(k => isCount(p.b[k]))).sort((a, b) => a.day.localeCompare(b.day)).slice(-30);
    if (!pts.length || pts.at(-1).day <= (svg.dataset.last || '')) return 'kept';
    const W = 720, H = 200, bw = Math.min(60, W / pts.length), max = Math.max(5, ...pts.map(p => p.total)); const kids = [];
    pts.forEach((p, i) => {
      const x = i * bw + 4, w = Math.max(2, bw - 8), bh = Math.max(2, Math.round((p.total / max) * (H - 50)));
      kids.push(sv('rect', { class: 'b', x, y: H - 30 - bh, width: w, height: bh }), sv('text', { class: 'v', x: x + w / 2, y: H - 36 - bh, 'text-anchor': 'middle' }, p.total), sv('text', { class: 'w', x: x + w / 2, y: H - 12, 'text-anchor': 'middle' }, p.day.slice(5)));
    });
    svg.replaceChildren(...kids); svg.dataset.last = pts.at(-1).day;
    svg.setAttribute('aria-label', 'New CVEs in NVD per complete UTC day: ' + pts.map(p => `${p.day} ${p.total}`).join('; '));
    const t = $('p-day-table');
    if (t) { const head = t.rows[0]; t.replaceChildren(head, ...pts.slice().reverse().map(p => { const tr = el('tr'); tr.append(el('td', p.day), el('td', p.total), ...DAYB.map(k => el('td', p.b[k]))); return tr; })); }
    const c = $('p-day-count'); if (c) c.textContent = String(m.size);
    return 'live';
  }

  async function refresh() {
    const out = [];
    for (const [name, fn, u] of [['KEV', kev, SRC.kev], ['NVD', nvd, SRC.nvd]]) {
      try { const data = await get(u); const r = fn(data); out.push(`${name}: ${r === 'live' ? 'the latest file' : 'the built copy is already the latest'}`); if (name === 'NVD') { try { await days(data); } catch { /* the built days stay */ } } }
      catch (e) { out.push(`${name}: the built copy (the latest file did not pass its checks or could not be read)`); const [id, src] = name === 'KEV' ? ['p-kev-state', $('p-kev-svg')] : ['p-nvd-state', $('p-nvd-read')]; if (src && src.dataset.read) mark(id, src.dataset.read); }
    }
    const s = $('p-live'); if (s) s.textContent = `Figures shown: ${out.join('; ')}. Checked ${new Date().toISOString().slice(11, 16)} UTC, from data.promptugal.news.`;
  }
  refresh();
  setInterval(refresh, 10 * 60 * 1000);
})();
