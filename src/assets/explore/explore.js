// The data explorer of cyber.promptugal.news (cyber.b@PrompTugal.dinis, 19 November 2026).
// Everything runs in the reader's browser: the JSON is read from data.promptugal.news and this site, loaded into
// in-memory tables, drawn, browsed and queried with SQLite (sql.js 1.10.3, vendored, MIT). Nothing is sent anywhere.
// Safety: third-party text (vendor, product, CNA names, descriptions) is only ever set with textContent; links are
// built only from a validated CVE id to nvd.nist.gov. No innerHTML anywhere in this file.
'use strict';
(() => {
  const SRC = {
    kev: 'https://data.promptugal.news/api/v1/cisa-kev/latest.json',
    nvd: 'https://data.promptugal.news/api/v1/nvd-cve/latest.json',
    pulse: '/api/v1/pulse/index.json',
  };
  const SQLJS = '/assets/vendor/sql.js-1.10.3/';
  const CVE = /^CVE-\d{4}-\d{4,7}$/;
  const SVGNS = 'http://www.w3.org/2000/svg';
  const $ = id => document.getElementById(id);
  const el = (tag, attrs = {}, text) => { const e = document.createElement(tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (text !== undefined) e.textContent = String(text); return e; };
  const sv = (tag, attrs = {}, text) => { const e = document.createElementNS(SVGNS, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); if (text !== undefined) e.textContent = String(text); return e; };
  const str = (x, max = 300) => (typeof x === 'string' ? x.slice(0, max) : '');
  const int = x => (Number.isFinite(x) ? x : null);
  const nvdLink = id => (CVE.test(id) ? `https://nvd.nist.gov/vuln/detail/${id}` : null);
  const status = m => { $('x-status').textContent = m; };

  async function getJSON(u) {
    const r = await fetch(u, { redirect: 'error', credentials: 'omit', headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error(`${u}: HTTP ${r.status}`);
    return r.json();
  }

  // ---------- data, normalised to plain rows of strings and numbers ----------
  const D = { kev: [], kevCwe: [], nvd: [], nvdProd: [], weekly: [], meta: {} };
  function load(kev, nvd, pulse) {
    for (const v of Array.isArray(kev.vulnerabilities) ? kev.vulnerabilities : []) {
      const id = str(v.cveID, 30); if (!CVE.test(id)) continue;
      const cwes = Array.isArray(v.cwes) ? v.cwes.map(c => str(c, 20)).filter(c => /^CWE-\d+$|^NVD-CWE-/.test(c)) : [];
      D.kev.push({ cve: id, vendor: str(v.vendorProject, 120), product: str(v.product, 160), name: str(v.vulnerabilityName, 300), date_added: str(v.dateAdded, 10), due_date: str(v.dueDate, 10), ransomware: str(v.knownRansomwareCampaignUse, 20), cwes: cwes.join(' ') });
      for (const c of cwes) D.kevCwe.push({ cve: id, cwe: c });
    }
    for (const c of Array.isArray(nvd.cves) ? nvd.cves : []) {
      const id = str(c.id, 30); if (!CVE.test(id)) continue;
      const cv = c.cvss || {};
      D.nvd.push({ cve: id, published: str(c.published, 25), last_modified: str(c.lastModified, 25), status: str(c.vulnStatus, 40), cna: str(c.cna, 120), cvss_version: str(cv.version, 5), score: int(cv.score), severity: str(cv.severity, 12) || 'unscored', products_from: str(c.products_from, 5) });
      for (const p of Array.isArray(c.products) ? c.products.slice(0, 50) : []) D.nvdProd.push({ cve: id, vendor: str(p.vendor, 120), product: str(p.product, 160) });
    }
    const s = (pulse.series || []).find(x => x.id === 'kev-added-weekly');
    for (const p of s ? s.points : []) if (/^\d{4}-\d{2}-\d{2}$/.test(p.week) && Number.isInteger(p.total)) D.weekly.push({ week: p.week, total: p.total, partial: p.partial ? 1 : 0 });
    D.meta = { kevRead: str(kev.read_at, 25), nvdRead: str(nvd.read_at, 25), notice: str(nvd.notice, 200) };
  }

  // ---------- small helpers for counting and drawing ----------
  const countBy = (rows, key) => { const m = new Map(); for (const r of rows) { const k = typeof key === 'function' ? key(r) : r[key]; if (k) m.set(k, (m.get(k) || 0) + 1); } return [...m.entries()].sort((a, b) => b[1] - a[1]); };
  function barsH(target, pairs, title, onClick) {
    const n = pairs.length, W = 640, row = 22, H = n * row + 10, max = Math.max(1, ...pairs.map(p => p[1]));
    const svg = sv('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': title });
    pairs.forEach(([k, v], i) => {
      const y = i * row + 4, w = Math.max(2, Math.round((v / max) * (W - 260)));
      const g = sv('g', { class: onClick ? 'x-click' : '' });
      g.append(sv('text', { x: 190, y: y + 14, 'text-anchor': 'end', class: 'x-lab' }, k.length > 30 ? k.slice(0, 29) + '…' : k));
      g.append(sv('rect', { x: 200, y, width: w, height: row - 6, class: 'x-bar' }));
      g.append(sv('text', { x: 206 + w, y: y + 14, class: 'x-val' }, v));
      const t = sv('title', {}, `${k}: ${v}`); g.append(t);
      if (onClick) g.addEventListener('click', () => onClick(k));
      svg.append(g);
    });
    target.replaceChildren(el('h3', {}, title), svg);
  }
  function barsV(target, pairs, title, cls = 'x-bar') {
    const W = 760, H = 220, n = pairs.length, bw = W / Math.max(1, n), max = Math.max(1, ...pairs.map(p => p[1]));
    const svg = sv('svg', { viewBox: `0 0 ${W} ${H + 24}`, role: 'img', 'aria-label': title });
    pairs.forEach(([k, v], i) => {
      const h = Math.round((v / max) * (H - 20)), x = i * bw;
      const r = sv('rect', { x: x + 1, y: H - h, width: Math.max(1, bw - 2), height: h, class: cls }); r.append(sv('title', {}, `${k}: ${v}`)); svg.append(r);
      if (n <= 24 || i % Math.ceil(n / 12) === 0) svg.append(sv('text', { x: x + bw / 2, y: H + 16, 'text-anchor': 'middle', class: 'x-tick' }, k));
    });
    target.replaceChildren(el('h3', {}, title), svg);
  }

  // ---------- overview ----------
  function overview() {
    const months = countBy(D.kev, r => r.date_added.slice(0, 7)).sort((a, b) => a[0].localeCompare(b[0]));
    barsV($('x-kev-months'), months, `Added to CISA KEV per month (${D.kev.length} CVEs in all)`);
    barsH($('x-kev-vendors'), countBy(D.kev, 'vendor').slice(0, 15), 'CISA KEV: the 15 vendors with most entries (click to browse)', v => { $('x-kev-q').value = v; tab('kev'); browseKev(); });
    barsH($('x-kev-cwes'), countBy(D.kevCwe, 'cwe').slice(0, 12), 'CISA KEV: the most common weakness types (CWE)');
    barsH($('x-kev-ransom'), countBy(D.kev, 'ransomware'), 'CISA KEV: known use in ransomware campaigns');
    const bands = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'unscored'];
    const sev = countBy(D.nvd, 'severity'); const sevMap = new Map(sev);
    barsH($('x-nvd-sev'), bands.map(b => [b, sevMap.get(b) || 0]), `NVD: CVEs new or modified in the 24 hours before ${D.meta.nvdRead}, by severity`);
    const hist = Array.from({ length: 10 }, (_, i) => [`${i}-${i + 1}`, 0]);
    for (const r of D.nvd) if (r.score !== null) hist[Math.min(9, Math.floor(r.score))][1]++;
    barsV($('x-nvd-score'), hist, 'NVD: CVSS base scores in the same window', 'x-bar2');
    barsH($('x-nvd-vendors'), countBy(D.nvdProd, 'vendor').slice(0, 15), 'NVD: vendors named most often in the same window');
  }

  // ---------- browse ----------
  const B = { kev: { sort: 'date_added', dir: -1, page: 0 }, nvd: { sort: 'last_modified', dir: -1, page: 0 } };
  function table(target, rows, cols, state, redraw) {
    const per = 50, pages = Math.max(1, Math.ceil(rows.length / per)); state.page = Math.min(state.page, pages - 1);
    const sorted = rows.slice().sort((a, b) => { const x = a[state.sort], y = b[state.sort]; return (x === y ? 0 : x === null ? 1 : y === null ? -1 : x < y ? -1 : 1) * state.dir; });
    const t = el('table'); const hr = el('tr');
    for (const [k, label] of cols) { const th = el('th', { tabindex: 0, class: 'x-sort' }, label + (state.sort === k ? (state.dir < 0 ? ' ▼' : ' ▲') : '')); th.addEventListener('click', () => { state.dir = state.sort === k ? -state.dir : -1; state.sort = k; redraw(); }); hr.append(th); }
    t.append(hr);
    for (const r of sorted.slice(state.page * per, state.page * per + per)) {
      const tr = el('tr');
      for (const [k] of cols) {
        const td = el('td'); const v = r[k];
        if (k === 'cve' && nvdLink(v)) td.append(el('a', { href: nvdLink(v), rel: 'noopener noreferrer' }, v)); else td.textContent = v === null ? '' : String(v);
        tr.append(td);
      }
      t.append(tr);
    }
    const nav = el('p', { class: 'x-nav' });
    const prev = el('button', { type: 'button' }, 'Previous'); prev.disabled = state.page === 0; prev.addEventListener('click', () => { state.page--; redraw(); });
    const next = el('button', { type: 'button' }, 'Next'); next.disabled = state.page >= pages - 1; next.addEventListener('click', () => { state.page++; redraw(); });
    nav.append(prev, el('span', {}, ` ${rows.length} rows · page ${state.page + 1} of ${pages} `), next);
    const wrap = el('div', { class: 'scroll' }); wrap.append(t);
    target.replaceChildren(nav, wrap);
  }
  const match = (r, q, keys) => !q || keys.some(k => String(r[k] || '').toLowerCase().includes(q));
  function browseKev() {
    const q = $('x-kev-q').value.trim().toLowerCase(), rs = $('x-kev-r').value;
    const rows = D.kev.filter(r => match(r, q, ['cve', 'vendor', 'product', 'name', 'cwes']) && (!rs || r.ransomware === rs));
    table($('x-kev-table'), rows, [['cve', 'CVE'], ['vendor', 'Vendor'], ['product', 'Product'], ['name', 'Name'], ['date_added', 'Added'], ['ransomware', 'Ransomware'], ['cwes', 'CWE']], B.kev, browseKev);
  }
  function browseNvd() {
    const q = $('x-nvd-q').value.trim().toLowerCase(), sv_ = $('x-nvd-s').value;
    const prods = new Map(); for (const p of D.nvdProd) { const a = prods.get(p.cve) || []; if (a.length < 3) a.push(`${p.vendor} ${p.product}`); prods.set(p.cve, a); }
    const rows = D.nvd.map(r => ({ ...r, products: (prods.get(r.cve) || []).join('; ') })).filter(r => match(r, q, ['cve', 'cna', 'products', 'status']) && (!sv_ || r.severity === sv_));
    table($('x-nvd-table'), rows, [['cve', 'CVE'], ['severity', 'Severity'], ['score', 'Score'], ['products', 'Products (first 3)'], ['cna', 'CNA'], ['status', 'Status'], ['published', 'Published'], ['last_modified', 'Modified']], B.nvd, browseNvd);
  }

  // ---------- graph: vendors and the weakness types of their known-exploited CVEs ----------
  function graph() {
    const topN = +$('x-g-n').value, topC = +$('x-g-c').value; $('x-g-nv').textContent = topN; $('x-g-cv').textContent = topC;
    const vendors = countBy(D.kev, 'vendor').slice(0, topN).map(x => x[0]); const vset = new Set(vendors);
    const byCve = new Map(D.kev.map(r => [r.cve, r.vendor]));
    const all = new Map(), cweW = new Map();
    for (const { cve, cwe } of D.kevCwe) { const v = byCve.get(cve); if (vset.has(v)) { const k = `${v}\u0000${cwe}`; all.set(k, (all.get(k) || 0) + 1); cweW.set(cwe, (cweW.get(cwe) || 0) + 1); } }
    const cwes = [...cweW.entries()].sort((a, b) => b[1] - a[1]).slice(0, topC).map(x => x[0]); const cset = new Set(cwes);
    const nodes = [...vendors.map(id => ({ id, kind: 'v' })), ...cwes.map(id => ({ id, kind: 'c' }))];
    const idx = new Map(nodes.map((n, i) => [n.id + n.kind, i]));
    const links = [];
    for (const [k, w] of all) { const [v, c] = k.split('\u0000'); if (cset.has(c)) links.push({ s: idx.get(v + 'v'), t: idx.get(c + 'c'), w }); }
    nodes.forEach((n, i) => { const a = (i / nodes.length) * 2 * Math.PI, r = n.kind === 'v' ? 120 : 260; n.x = Math.cos(a) * r; n.y = Math.sin(a) * r; n.vx = 0; n.vy = 0; n.deg = 0; });
    for (const l of links) { nodes[l.s].deg += l.w; nodes[l.t].deg += l.w; }
    for (let step = 0; step < 500; step++) { // a simple force layout, computed before drawing
      const cool = 1 - step / 500;
      for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j]; let dx = a.x - b.x, dy = a.y - b.y; const d2 = Math.max(400, dx * dx + dy * dy), f = 9000 / d2, d = Math.sqrt(d2);
        a.vx += dx / d * f; a.vy += dy / d * f; b.vx -= dx / d * f; b.vy -= dy / d * f;
      }
      for (const l of links) { const a = nodes[l.s], b = nodes[l.t], dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1, f = (d - 110) * 0.02 * Math.min(3, 1 + Math.log2(l.w)); a.vx += dx / d * f; a.vy += dy / d * f; b.vx -= dx / d * f; b.vy -= dy / d * f; }
      for (const n of nodes) { n.vx -= n.x * 0.01; n.vy -= n.y * 0.01; n.x += Math.max(-20, Math.min(20, n.vx)) * cool; n.y += Math.max(-20, Math.min(20, n.vy)) * cool; n.vx *= 0.6; n.vy *= 0.6; }
    }
    const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y), pad = 70;
    const minX = Math.min(...xs) - pad, minY = Math.min(...ys) - 30, W = Math.max(...xs) - minX + pad + 60, H = Math.max(...ys) - minY + 30;
    const svg = sv('svg', { viewBox: `${minX.toFixed(0)} ${minY.toFixed(0)} ${W.toFixed(0)} ${H.toFixed(0)}`, role: 'img', 'aria-label': 'Graph of the top vendors in CISA KEV and the weakness types of their CVEs' });
    const lg = sv('g'), ng = sv('g'); svg.append(lg, ng);
    for (const l of links) { const a = nodes[l.s], b = nodes[l.t]; const e = sv('line', { class: 'x-edge', x1: a.x.toFixed(1), y1: a.y.toFixed(1), x2: b.x.toFixed(1), y2: b.y.toFixed(1), 'stroke-width': Math.min(7, 0.6 + Math.log2(1 + l.w)).toFixed(1) }); e.append(sv('title', {}, `${a.id} · ${b.id}: ${l.w} CVEs`)); lg.append(e); }
    for (const n of nodes) {
      const g = sv('g', { class: (n.kind === 'v' ? 'x-nv' : 'x-nc') + ' x-click', transform: `translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`, tabindex: 0 });
      g.append(sv('circle', { r: Math.min(26, 5 + Math.sqrt(n.deg) * 1.5).toFixed(1) }));
      g.append(sv('text', { dx: 10, dy: 4, class: n.kind === 'v' ? 'x-glab x-glab-v' : 'x-glab' }, n.id.length > 24 ? n.id.slice(0, 23) + '…' : n.id));
      g.append(sv('title', {}, `${n.kind === 'v' ? 'Vendor' : 'Weakness'} ${n.id}: ${n.deg} CVEs in this view. Click to browse.`));
      const go = () => { $('x-kev-q').value = n.id; tab('kev'); browseKev(); };
      g.addEventListener('click', go); g.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
      ng.append(g);
    }
    $('x-graph').replaceChildren(svg);
  }

  // ---------- SQL, in the browser ----------
  let db = null;
  const EXAMPLES = [
    ['Top vendors in KEV', 'SELECT vendor, COUNT(*) AS cves FROM kev GROUP BY vendor ORDER BY cves DESC LIMIT 20;'],
    ['KEV additions per year', "SELECT substr(date_added, 1, 4) AS year, COUNT(*) AS added FROM kev GROUP BY year ORDER BY year;"],
    ['Ransomware-linked CVEs by vendor', "SELECT vendor, COUNT(*) AS cves FROM kev WHERE ransomware = 'Known' GROUP BY vendor ORDER BY cves DESC LIMIT 20;"],
    ['Most common weaknesses in KEV', 'SELECT cwe, COUNT(*) AS cves FROM kev_cwe GROUP BY cwe ORDER BY cves DESC LIMIT 20;'],
    ['NVD window: critical CVEs and their products', "SELECT n.cve, n.score, p.vendor, p.product FROM nvd n JOIN nvd_product p USING (cve) WHERE n.severity = 'CRITICAL' ORDER BY n.score DESC LIMIT 50;"],
    ['In both KEV and the NVD window', 'SELECT k.cve, k.vendor, k.product, n.severity, n.score FROM kev k JOIN nvd n USING (cve) ORDER BY k.date_added DESC;'],
    ['KEV weeks with the most additions', 'SELECT week, total FROM kev_weekly ORDER BY total DESC LIMIT 15;'],
  ];
  async function sqlInit() {
    if (db) return db;
    status('Loading SQLite (sql.js, in your browser)…');
    const SQL = await window.initSqlJs({ locateFile: f => SQLJS + f });
    db = new SQL.Database();
    db.run(`CREATE TABLE kev(cve TEXT, vendor TEXT, product TEXT, name TEXT, date_added TEXT, due_date TEXT, ransomware TEXT, cwes TEXT);
CREATE TABLE kev_cwe(cve TEXT, cwe TEXT);
CREATE TABLE nvd(cve TEXT, published TEXT, last_modified TEXT, status TEXT, cna TEXT, cvss_version TEXT, score REAL, severity TEXT, products_from TEXT);
CREATE TABLE nvd_product(cve TEXT, vendor TEXT, product TEXT);
CREATE TABLE kev_weekly(week TEXT, total INTEGER, partial INTEGER);`);
    const ins = (t, cols, rows) => { db.run('BEGIN'); const st = db.prepare(`INSERT INTO ${t} VALUES (${cols.map(() => '?').join(',')})`); for (const r of rows) st.run(cols.map(c => r[c])); st.free(); db.run('COMMIT'); };
    ins('kev', ['cve', 'vendor', 'product', 'name', 'date_added', 'due_date', 'ransomware', 'cwes'], D.kev);
    ins('kev_cwe', ['cve', 'cwe'], D.kevCwe);
    ins('nvd', ['cve', 'published', 'last_modified', 'status', 'cna', 'cvss_version', 'score', 'severity', 'products_from'], D.nvd);
    ins('nvd_product', ['cve', 'vendor', 'product'], D.nvdProd);
    ins('kev_weekly', ['week', 'total', 'partial'], D.weekly);
    status(`SQLite ready: kev ${D.kev.length}, kev_cwe ${D.kevCwe.length}, nvd ${D.nvd.length}, nvd_product ${D.nvdProd.length}, kev_weekly ${D.weekly.length} rows.`);
    return db;
  }
  let lastResult = null;
  async function runSql() {
    const out = $('x-sql-out');
    try {
      const d = await sqlInit();
      const res = d.exec($('x-sql').value.slice(0, 5000));
      const r = res[res.length - 1];
      if (!r) { out.replaceChildren(el('p', {}, 'No rows.')); lastResult = null; return; }
      lastResult = r;
      const t = el('table'), hr = el('tr'); r.columns.forEach(c => hr.append(el('th', {}, c))); t.append(hr);
      for (const row of r.values.slice(0, 1000)) { const tr = el('tr'); row.forEach((v, i) => { const td = el('td'); if (r.columns[i] === 'cve' && nvdLink(v)) td.append(el('a', { href: nvdLink(v), rel: 'noopener noreferrer' }, v)); else td.textContent = v === null ? '' : String(v); tr.append(td); }); t.append(tr); }
      const wrap = el('div', { class: 'scroll' }); wrap.append(t);
      out.replaceChildren(el('p', {}, `${r.values.length} rows${r.values.length > 1000 ? ' (first 1000 shown; the CSV has all)' : ''}.`), wrap);
    } catch (e) { out.replaceChildren(el('p', { class: 'x-err' }, `Error: ${String(e && e.message || e).slice(0, 300)}`)); lastResult = null; }
  }
  function csv() {
    if (!lastResult) return;
    const q = v => { const s = v === null ? '' : String(v); const t = /^[=+\-@\t\r]/.test(s) ? "'" + s : s; return /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
    const text = [lastResult.columns.map(q).join(','), ...lastResult.values.map(r => r.map(q).join(','))].join('\n') + '\n';
    const a = el('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/csv' })), download: 'cyber-promptugal-query.csv' }); document.body.append(a); a.click(); a.remove();
  }

  // ---------- tabs and start ----------
  const TABS = ['overview', 'kev', 'nvd', 'graph', 'sql'];
  function tab(name) {
    for (const t of TABS) { $(`x-tab-${t}`).setAttribute('aria-selected', String(t === name)); $(`x-p-${t}`).hidden = t !== name; }
    if (name === 'graph') graph();
    try { localStorage.setItem('cyber-explore-tab', name); } catch { /* private mode */ }
  }
  async function start() {
    status('Reading the JSON from data.promptugal.news…');
    try {
      const [kev, nvd, pulse] = await Promise.all([getJSON(SRC.kev), getJSON(SRC.nvd), getJSON(SRC.pulse)]);
      load(kev, nvd, pulse);
    } catch (e) { status(`Could not load the data: ${String(e && e.message || e).slice(0, 200)}`); return; }
    $('x-prov-kev').textContent = `CISA KEV via ${SRC.kev}, read ${D.meta.kevRead}. Underlying data CC0 1.0; the file CC BY 4.0, PrompTugal.news.`;
    $('x-prov-nvd').textContent = `NVD CVE API 2.0 via ${SRC.nvd}, read ${D.meta.nvdRead}. ${D.meta.notice}`;
    status(`Loaded ${D.kev.length} KEV entries and ${D.nvd.length} NVD records in your browser.`);
    for (const t of TABS) $(`x-tab-${t}`).addEventListener('click', () => tab(t));
    $('x-kev-q').addEventListener('input', () => { B.kev.page = 0; browseKev(); }); $('x-kev-r').addEventListener('change', () => { B.kev.page = 0; browseKev(); });
    $('x-nvd-q').addEventListener('input', () => { B.nvd.page = 0; browseNvd(); }); $('x-nvd-s').addEventListener('change', () => { B.nvd.page = 0; browseNvd(); });
    $('x-g-n').addEventListener('change', graph); $('x-g-c').addEventListener('change', graph);
    const ex = $('x-sql-ex'); for (const [label, q] of EXAMPLES) { const b = el('button', { type: 'button' }, label); b.addEventListener('click', () => { $('x-sql').value = q; runSql(); }); ex.append(b); }
    $('x-sql-run').addEventListener('click', runSql); $('x-sql-csv').addEventListener('click', csv);
    $('x-sql').addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runSql(); });
    overview(); browseKev(); browseNvd();
    let first = 'overview'; try { const s = localStorage.getItem('cyber-explore-tab'); if (TABS.includes(s)) first = s; } catch { /* none */ }
    tab(first);
  }
  start();
})();
