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

  // ---------- links: every filter is a URL (#tab=kev&vendor=...), so every click can be shared or opened anew ----------
  const KEYS = ['tab', 'cve', 'kq', 'vendor', 'product', 'cwe', 'month', 'week', 'ransom', 'nq', 'sev', 'nvendor', 'cna', 'score'];
  const LABEL = { kq: 'search', vendor: 'vendor', product: 'product', cwe: 'weakness', month: 'month added', week: 'week of', ransom: 'ransomware use', nq: 'search', sev: 'severity', nvendor: 'vendor', cna: 'CNA', score: 'CVSS band from' };
  const KEV_KEYS = ['kq', 'vendor', 'product', 'cwe', 'month', 'week', 'ransom'], NVD_KEYS = ['nq', 'sev', 'nvendor', 'cna', 'score'];
  function state() { const p = new URLSearchParams(location.hash.slice(1)); const s = {}; for (const k of KEYS) { const v = p.get(k); if (v) s[k] = v.slice(0, 200); } return s; }
  // a link keeps the filters of its own tab only: KEV filters never ride into NVD links, and a CVE page starts clean
  function href(change, base = state()) {
    const keep = change.tab === 'kev' ? KEV_KEYS : change.tab === 'nvd' ? NVD_KEYS : change.tab === 'cve' ? ['cve'] : [];
    const s = { ...Object.fromEntries(keep.filter(k => base[k]).map(k => [k, base[k]])), ...change }; const p = new URLSearchParams();
    for (const k of KEYS) if (s[k] !== undefined && s[k] !== null && s[k] !== '') p.set(k, s[k]);
    return '#' + p.toString();
  }
  const link = (text, change, extra = {}) => { const a = el('a', { href: href(change), ...extra }, text); return a; };
  const svgLink = change => sv('a', { href: href(change), class: 'x-click' });
  const monday = d => { const t = new Date(d + 'T00:00:00Z'); if (Number.isNaN(+t)) return ''; t.setUTCDate(t.getUTCDate() - ((t.getUTCDay() + 6) % 7)); return t.toISOString().slice(0, 10); };
  const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'unscored'];

  // ---------- small helpers for counting and drawing ----------
  const countBy = (rows, key) => { const m = new Map(); for (const r of rows) { const k = typeof key === 'function' ? key(r) : r[key]; if (k) m.set(k, (m.get(k) || 0) + 1); } return [...m.entries()].sort((a, b) => b[1] - a[1]); };
  function barsH(target, pairs, title, toChange) {
    const n = pairs.length, W = 640, row = 22, H = n * row + 10, max = Math.max(1, ...pairs.map(p => p[1]));
    const svg = sv('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': title });
    pairs.forEach(([k, v], i) => {
      const y = i * row + 4, w = Math.max(2, Math.round((v / max) * (W - 260)));
      const g = toChange ? svgLink(toChange(k)) : sv('g');
      g.append(sv('text', { x: 190, y: y + 14, 'text-anchor': 'end', class: 'x-lab' }, k.length > 30 ? k.slice(0, 29) + '…' : k));
      g.append(sv('rect', { x: 200, y, width: w, height: row - 6, class: 'x-bar' }));
      g.append(sv('text', { x: 206 + w, y: y + 14, class: 'x-val' }, v));
      g.append(sv('title', {}, `${k}: ${v}${toChange ? '. Click to browse.' : ''}`));
      svg.append(g);
    });
    target.replaceChildren(el('h3', {}, title), svg);
  }
  function barsV(target, pairs, title, toChange, cls = 'x-bar') {
    const W = 760, H = 220, n = pairs.length, bw = W / Math.max(1, n), max = Math.max(1, ...pairs.map(p => p[1]));
    const svg = sv('svg', { viewBox: `0 0 ${W} ${H + 24}`, role: 'img', 'aria-label': title });
    pairs.forEach(([k, v], i) => {
      const h = Math.max(1, Math.round((v / max) * (H - 20))), x = i * bw;
      const g = toChange ? svgLink(toChange(k)) : sv('g');
      g.append(sv('rect', { x: x, y: 0, width: bw, height: H, class: 'x-hit' }));
      const r = sv('rect', { x: x + 1, y: H - h, width: Math.max(1, bw - 2), height: h, class: cls }); g.append(r);
      g.append(sv('title', {}, `${k}: ${v}${toChange ? '. Click to browse.' : ''}`));
      svg.append(g);
      if (n <= 24 || i % Math.ceil(n / 12) === 0) svg.append(sv('text', { x: x + bw / 2, y: H + 16, 'text-anchor': 'middle', class: 'x-tick' }, k));
    });
    target.replaceChildren(el('h3', {}, title), svg);
  }

  // ---------- overview: every bar is a link to the records behind it ----------
  function overview() {
    const months = countBy(D.kev, r => r.date_added.slice(0, 7)).sort((a, b) => a[0].localeCompare(b[0]));
    barsV($('x-kev-months'), months, `Added to CISA KEV per month (${D.kev.length} CVEs in all). Click a month to see its CVEs.`, k => ({ tab: 'kev', month: k }));
    barsH($('x-kev-vendors'), countBy(D.kev, 'vendor').slice(0, 15), 'CISA KEV: the 15 vendors with most entries', k => ({ tab: 'kev', vendor: k }));
    barsH($('x-kev-cwes'), countBy(D.kevCwe, 'cwe').slice(0, 12), 'CISA KEV: the most common weakness types (CWE)', k => ({ tab: 'kev', cwe: k }));
    barsH($('x-kev-ransom'), countBy(D.kev, 'ransomware'), 'CISA KEV: known use in ransomware campaigns', k => ({ tab: 'kev', ransom: k }));
    const sevMap = new Map(countBy(D.nvd, 'severity'));
    barsH($('x-nvd-sev'), SEV.map(b => [b, sevMap.get(b) || 0]), `NVD: CVEs new or modified in the 24 hours before ${D.meta.nvdRead}, by severity`, k => ({ tab: 'nvd', sev: k }));
    const hist = Array.from({ length: 10 }, (_, i) => [`${i}-${i + 1}`, 0]);
    for (const r of D.nvd) if (r.score !== null) hist[Math.max(0, Math.min(9, Math.floor(r.score)))][1]++;
    barsV($('x-nvd-score'), hist, 'NVD: CVSS base scores in the same window', k => ({ tab: 'nvd', score: k.split('-')[0] }), 'x-bar2');
    barsH($('x-nvd-vendors'), countBy(D.nvdProd, 'vendor').slice(0, 15), 'NVD: vendors named most often in the same window', k => ({ tab: 'nvd', nvendor: k }));
  }

  // ---------- browse: every cell is a filter, every CVE a page ----------
  const B = { kev: { sort: 'date_added', dir: -1, page: 0 }, nvd: { sort: 'last_modified', dir: -1, page: 0 } };
  function chips(target, keys, s, tabName) {
    const on = keys.filter(k => s[k]);
    if (!on.length) { target.replaceChildren(); return; }
    const p = el('p', { class: 'x-chips' }, 'Filters: ');
    for (const k of on) { const a = link(`${LABEL[k]}: ${s[k]} ×`, { [k]: '', tab: tabName }, { class: 'x-chip', title: 'Remove this filter' }); p.append(a, ' '); }
    const clear = {}; for (const k of keys) clear[k] = ''; p.append(link('clear all', { ...clear, tab: tabName }, { class: 'x-chip x-chip-clear' }));
    target.replaceChildren(p);
  }
  // cell(k, v, row) returns a node for a value: a filter link, a CVE page link, or text
  function table(target, rows, cols, st, redraw, cell) {
    const per = 50, pages = Math.max(1, Math.ceil(rows.length / per)); st.page = Math.min(st.page, pages - 1);
    const sorted = rows.slice().sort((a, b) => { const x = a[st.sort], y = b[st.sort]; return (x === y ? 0 : x === null ? 1 : y === null ? -1 : x < y ? -1 : 1) * st.dir; });
    const t = el('table'); const hr = el('tr');
    for (const [k, label] of cols) { const th = el('th', { tabindex: 0, class: 'x-sort', title: 'Sort' }, label + (st.sort === k ? (st.dir < 0 ? ' ▼' : ' ▲') : '')); const go = () => { st.dir = st.sort === k ? -st.dir : -1; st.sort = k; redraw(); }; th.addEventListener('click', go); th.addEventListener('keydown', e => { if (e.key === 'Enter') go(); }); hr.append(th); }
    t.append(hr);
    for (const r of sorted.slice(st.page * per, st.page * per + per)) {
      const tr = el('tr');
      for (const [k] of cols) { const td = el('td'); const node = cell(k, r[k], r); if (node) td.append(node); tr.append(td); }
      t.append(tr);
    }
    const nav = el('p', { class: 'x-nav' });
    const prev = el('button', { type: 'button' }, 'Previous'); prev.disabled = st.page === 0; prev.addEventListener('click', () => { st.page--; redraw(); });
    const next = el('button', { type: 'button' }, 'Next'); next.disabled = st.page >= pages - 1; next.addEventListener('click', () => { st.page++; redraw(); });
    nav.append(prev, el('span', {}, ` ${rows.length} rows · page ${st.page + 1} of ${pages} `), next);
    const wrap = el('div', { class: 'scroll' }); wrap.append(t);
    target.replaceChildren(nav, wrap);
  }
  const cveLink = id => (CVE.test(id) ? link(id, { tab: 'cve', cve: id }, { title: 'Everything on this CVE' }) : document.createTextNode(String(id || '')));
  const frag = (...nodes) => { const f = document.createDocumentFragment(); nodes.forEach((n, i) => { if (i) f.append(' '); f.append(n); }); return f; };
  function kevCell(k, v, r) {
    if (v === null || v === undefined || v === '') return null;
    if (k === 'cve') return cveLink(v);
    if (k === 'vendor') return link(v, { tab: 'kev', vendor: v }, { title: 'Only this vendor' });
    if (k === 'product') return link(v, { tab: 'kev', vendor: r.vendor, product: v }, { title: 'Only this product' });
    if (k === 'ransomware') return link(v, { tab: 'kev', ransom: v }, { title: 'Only this' });
    if (k === 'date_added') return frag(link(v, { tab: 'kev', week: monday(v), month: '' }, { title: 'Only the week this was added' }));
    if (k === 'cwes') return frag(...String(v).split(' ').filter(Boolean).map(c => link(c, { tab: 'kev', cwe: c }, { title: 'Only this weakness' })));
    return document.createTextNode(String(v));
  }
  function browseKev() {
    const s = state(); const q = (s.kq || '').trim().toLowerCase();
    if (document.activeElement !== $('x-kev-q')) $('x-kev-q').value = s.kq || ''; $('x-kev-r').value = ['Known', 'Unknown'].includes(s.ransom) ? s.ransom : '';
    chips($('x-kev-chips'), KEV_KEYS, s, 'kev');
    const rows = D.kev.filter(r => (!q || ['cve', 'vendor', 'product', 'name', 'cwes'].some(k => String(r[k]).toLowerCase().includes(q)))
      && (!s.vendor || r.vendor === s.vendor) && (!s.product || r.product === s.product) && (!s.ransom || r.ransomware === s.ransom)
      && (!s.cwe || r.cwes.split(' ').includes(s.cwe)) && (!s.month || r.date_added.slice(0, 7) === s.month) && (!s.week || monday(r.date_added) === s.week));
    table($('x-kev-table'), rows, [['cve', 'CVE'], ['vendor', 'Vendor'], ['product', 'Product'], ['name', 'Name'], ['date_added', 'Added'], ['ransomware', 'Ransomware'], ['cwes', 'CWE']], B.kev, browseKev, kevCell);
  }
  let prodsByCve = null;
  const prods = () => { if (!prodsByCve) { prodsByCve = new Map(); for (const p of D.nvdProd) { const a = prodsByCve.get(p.cve) || []; a.push(p); prodsByCve.set(p.cve, a); } } return prodsByCve; };
  function nvdCell(k, v, r) {
    if (k === 'products') { const ps = prods().get(r.cve) || []; return ps.length ? frag(...ps.slice(0, 3).map(p => link(`${p.vendor} ${p.product}`, { tab: 'nvd', nvendor: p.vendor }, { title: 'Only this vendor' }))) : null; }
    if (v === null || v === undefined || v === '') return null;
    if (k === 'cve') return cveLink(v);
    if (k === 'severity') return link(v, { tab: 'nvd', sev: v }, { title: 'Only this severity' });
    if (k === 'cna') return link(v, { tab: 'nvd', cna: v }, { title: 'Only this CNA' });
    if (k === 'score') return link(v, { tab: 'nvd', score: String(Math.max(0, Math.min(9, Math.floor(v)))) }, { title: 'This score band' });
    return document.createTextNode(String(v));
  }
  function browseNvd() {
    const s = state(); const q = (s.nq || '').trim().toLowerCase();
    if (document.activeElement !== $('x-nvd-q')) $('x-nvd-q').value = s.nq || ''; $('x-nvd-s').value = SEV.includes(s.sev) ? s.sev : '';
    chips($('x-nvd-chips'), NVD_KEYS, s, 'nvd');
    const ps = prods(); const sc = s.score !== undefined && /^\d$/.test(s.score) ? +s.score : null;
    const rows = D.nvd.map(r => ({ ...r, products: (ps.get(r.cve) || []).map(p => `${p.vendor} ${p.product}`).join('; ') }))
      .filter(r => (!q || ['cve', 'cna', 'products', 'status'].some(k => String(r[k]).toLowerCase().includes(q))) && (!s.sev || r.severity === s.sev)
        && (!s.cna || r.cna === s.cna) && (!s.nvendor || (ps.get(r.cve) || []).some(p => p.vendor === s.nvendor))
        && (sc === null || (r.score !== null && Math.max(0, Math.min(9, Math.floor(r.score))) === sc)));
    table($('x-nvd-table'), rows, [['cve', 'CVE'], ['severity', 'Severity'], ['score', 'Score'], ['products', 'Products (first 3)'], ['cna', 'CNA'], ['status', 'Status'], ['published', 'Published'], ['last_modified', 'Modified']], B.nvd, browseNvd, nvdCell);
  }

  // ---------- one page per CVE: everything we hold on it, every value a link ----------
  function cvePage() {
    const id = state().cve || ''; const out = $('x-cve');
    if (!CVE.test(id)) { out.replaceChildren(el('p', {}, 'Choose a CVE from Browse KEV, Browse NVD or SQL.')); return; }
    const k = D.kev.find(r => r.cve === id), n = D.nvd.find(r => r.cve === id), ps = prods().get(id) || [];
    const dl = el('dl', { class: 'x-dl' }); const row = (label, node) => { dl.append(el('dt', {}, label)); const dd = el('dd'); if (node) dd.append(node); else dd.textContent = 'not in the data we read'; dl.append(dd); };
    const box = [el('h2', {}, id)];
    if (k) {
      row('Known exploited (CISA KEV)', document.createTextNode(`yes, added ${k.date_added}`));
      row('Vendor', kevCell('vendor', k.vendor, k)); row('Product', kevCell('product', k.product, k)); row('Name', document.createTextNode(k.name));
      row('Added', kevCell('date_added', k.date_added, k)); row('CISA due date (US federal agencies)', document.createTextNode(k.due_date || ''));
      row('Known ransomware use', kevCell('ransomware', k.ransomware, k)); row('Weakness types', k.cwes ? kevCell('cwes', k.cwes, k) : null);
    } else row('Known exploited (CISA KEV)', document.createTextNode('not on the list as read'));
    if (n) {
      row('NVD severity', frag(nvdCell('severity', n.severity, n), document.createTextNode(n.score !== null ? `score ${n.score} (CVSS ${n.cvss_version})` : '')));
      row('NVD status', document.createTextNode(n.status)); row('CNA', nvdCell('cna', n.cna, n));
      row('Published', document.createTextNode(n.published)); row('Last modified', document.createTextNode(n.last_modified));
      row('Products in NVD', ps.length ? frag(...ps.map(p => link(`${p.vendor} ${p.product}`, { tab: 'nvd', nvendor: p.vendor }))) : null);
    } else row('NVD (latest 24-hour window)', document.createTextNode('not new or modified in the window we hold'));
    box.push(dl);
    const ext = el('p', { class: 'x-ext' }, 'At the source: ');
    ext.append(el('a', { href: `https://nvd.nist.gov/vuln/detail/${id}`, rel: 'noopener noreferrer' }, 'NVD'), ' · ', el('a', { href: `https://www.cve.org/CVERecord?id=${id}`, rel: 'noopener noreferrer' }, 'CVE.org'));
    if (k) ext.append(' · ', el('a', { href: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', rel: 'noopener noreferrer' }, 'CISA KEV catalogue'));
    box.push(ext);
    if (k) { const more = el('p', {}, 'More: '); more.append(link(`every KEV entry for ${k.vendor}`, { tab: 'kev', vendor: k.vendor, product: '', kq: '' }), ' · ', link(`every KEV entry added the week of ${monday(k.date_added)}`, { tab: 'kev', week: monday(k.date_added), vendor: '', product: '' })); box.push(more); }
    out.replaceChildren(...box);
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
    for (const [k, w] of all) { const [v, c] = k.split('\u0000'); if (cset.has(c)) links.push({ s: idx.get(v + 'v'), t: idx.get(c + 'c'), w, v, c }); }
    nodes.forEach((n, i) => { const a = (i / nodes.length) * 2 * Math.PI, r = n.kind === 'v' ? 120 : 260; n.x = Math.cos(a) * r; n.y = Math.sin(a) * r; n.vx = 0; n.vy = 0; n.deg = 0; });
    for (const l of links) { nodes[l.s].deg += l.w; nodes[l.t].deg += l.w; }
    for (let step = 0; step < 500; step++) {
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
    for (const l of links) {
      const a = nodes[l.s], b = nodes[l.t]; const ln = svgLink({ tab: 'kev', vendor: l.v, cwe: l.c });
      const e = sv('line', { class: 'x-edge', x1: a.x.toFixed(1), y1: a.y.toFixed(1), x2: b.x.toFixed(1), y2: b.y.toFixed(1), 'stroke-width': Math.max(3, Math.min(7, 0.6 + Math.log2(1 + l.w))).toFixed(1) });
      ln.append(e, sv('title', {}, `${a.id} · ${b.id}: ${l.w} CVEs. Click to see them.`)); lg.append(ln);
    }
    for (const n of nodes) {
      const g = svgLink(n.kind === 'v' ? { tab: 'kev', vendor: n.id, cwe: '' } : { tab: 'kev', cwe: n.id, vendor: '' });
      g.setAttribute('class', (n.kind === 'v' ? 'x-nv' : 'x-nc') + ' x-click'); g.setAttribute('transform', `translate(${n.x.toFixed(1)} ${n.y.toFixed(1)})`);
      g.append(sv('circle', { r: Math.min(26, 5 + Math.sqrt(n.deg) * 1.5).toFixed(1) }));
      g.append(sv('text', { dx: 10, dy: 4, class: n.kind === 'v' ? 'x-glab x-glab-v' : 'x-glab' }, n.id.length > 24 ? n.id.slice(0, 23) + '…' : n.id));
      g.append(sv('title', {}, `${n.kind === 'v' ? 'Vendor' : 'Weakness'} ${n.id}: ${n.deg} CVE-weakness links in this view. Click to browse.`));
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
      for (const row of r.values.slice(0, 1000)) { const tr = el('tr'); row.forEach((v, i) => { const td = el('td'); if (r.columns[i] === 'cve' && CVE.test(String(v))) td.append(cveLink(String(v))); else if (r.columns[i] === 'vendor' && v) td.append(link(String(v), { tab: 'kev', vendor: String(v) })); else if (r.columns[i] === 'cwe' && /^CWE-\d+$/.test(String(v))) td.append(link(String(v), { tab: 'kev', cwe: String(v) })); else if (r.columns[i] === 'week' && /^\d{4}-\d{2}-\d{2}$/.test(String(v))) td.append(link(String(v), { tab: 'kev', week: String(v) })); else td.textContent = v === null ? '' : String(v); tr.append(td); }); t.append(tr); }
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

  // ---------- tabs, the URL and start ----------
  const TABS = ['overview', 'kev', 'nvd', 'graph', 'sql', 'cve'];
  function render() {
    const s = state(); const name = TABS.includes(s.tab) ? s.tab : (s.cve ? 'cve' : 'overview');
    for (const t of TABS) { $(`x-tab-${t}`).setAttribute('aria-selected', String(t === name)); $(`x-p-${t}`).hidden = t !== name; }
    $('x-tab-cve').hidden = !s.cve; if (s.cve) $('x-tab-cve').textContent = s.cve;
    if (name === 'kev') { B.kev.page = 0; browseKev(); }
    if (name === 'nvd') { B.nvd.page = 0; browseNvd(); }
    if (name === 'graph') graph();
    if (name === 'cve') cvePage();
  }
  const setHash = change => { const h = href(change); if (h !== location.hash) location.hash = h; else render(); };
  const typeHash = change => { history.replaceState(null, '', href(change)); };
  async function start() {
    status('Reading the JSON from data.promptugal.news…');
    try {
      const [kev, nvd, pulse] = await Promise.all([getJSON(SRC.kev), getJSON(SRC.nvd), getJSON(SRC.pulse)]);
      load(kev, nvd, pulse);
    } catch (e) { status(`Could not load the data: ${String(e && e.message || e).slice(0, 200)}`); return; }
    $('x-prov-kev').textContent = `CISA KEV via ${SRC.kev}, read ${D.meta.kevRead}. Underlying data CC0 1.0; the file CC BY 4.0, PrompTugal.news.`;
    $('x-prov-nvd').textContent = `NVD CVE API 2.0 via ${SRC.nvd}, read ${D.meta.nvdRead}. ${D.meta.notice}`;
    status(`Loaded ${D.kev.length} KEV entries and ${D.nvd.length} NVD records in your browser. Every bar, value and node is a link.`);
    for (const t of TABS) $(`x-tab-${t}`).addEventListener('click', () => setHash({ tab: t }));
    $('x-kev-q').addEventListener('input', () => { typeHash({ tab: 'kev', kq: $('x-kev-q').value }); B.kev.page = 0; browseKev(); });
    $('x-kev-r').addEventListener('change', () => setHash({ tab: 'kev', ransom: $('x-kev-r').value }));
    $('x-nvd-q').addEventListener('input', () => { typeHash({ tab: 'nvd', nq: $('x-nvd-q').value }); B.nvd.page = 0; browseNvd(); });
    $('x-nvd-s').addEventListener('change', () => setHash({ tab: 'nvd', sev: $('x-nvd-s').value }));
    $('x-g-n').addEventListener('change', graph); $('x-g-c').addEventListener('change', graph);
    const ex = $('x-sql-ex'); for (const [label, q] of EXAMPLES) { const b = el('button', { type: 'button' }, label); b.addEventListener('click', () => { $('x-sql').value = q; runSql(); }); ex.append(b); }
    $('x-sql-run').addEventListener('click', runSql); $('x-sql-csv').addEventListener('click', csv);
    $('x-sql').addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runSql(); });
    overview();
    window.addEventListener('hashchange', () => { render(); const p = $('x-tabs'); if (p) p.scrollIntoView({ block: 'start' }); });
    render();
  }
  start();
})();
