// A proposed mapping of CISA KEV products to classes of use (Dinis Cruz, 18 Nov 2026, about 23:41 UTC: "I think that sounds
// quite good"). Reads the hand-written src/api/v1/sectors/mapping.json and the CVE store (src/api/v1/cve/), counts the CVEs
// on KEV now per class, and writes _site/api/v1/sectors/index.json and /sectors/. A proposal, not sector exposure.
// The mapping is checked and a fault stops the build. Every value is escaped; links are built from KEV's own strings.
// cyber.b@PrompTugal.dinis, 21 Nov 2026.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const CVE = /^CVE-\d{4}-\d{4,7}$/;
export function loadKev(dir = 'src/api/v1/cve') {
  const out = [];
  for (const y of readdirSync(dir)) if (/^\d{4}$/.test(y)) for (const f of readdirSync(join(dir, y))) {
    if (!f.endsWith('.json') || !CVE.test(f.slice(0, -5))) continue;
    const d = JSON.parse(readFileSync(join(dir, y, f), 'utf8')); const k = d.kev && d.kev.at(-1);
    if (k && k.record) out.push({ id: d.id, vendor: String(k.record.vendor), product: String(k.record.product) });
  }
  return out;
}

export function check(m, kev) {
  const fail = s => { throw new Error(`sectors: ${s}`); };
  if (m.status !== 'proposal') fail('the mapping must say status "proposal"');
  for (const k of ['about', 'notice', 'by', 'made', 'from', 'precedence']) if (typeof m[k] !== 'string' || !m[k].trim()) fail(`the mapping has no ${k}`);
  const classes = new Map();
  for (const c of m.classes || []) { if (!/^[a-z-]+$/.test(c.id || '') || classes.has(c.id) || !c.name || !c.reason || !Array.isArray(c.typical_use) || !c.typical_use.length || typeof c.name !== 'string' || typeof c.reason !== 'string') fail(`bad class ${JSON.stringify(c.id)}`); classes.set(c.id, c); }
  const vendors = new Set(kev.map(e => e.vendor)), pairs = new Set(kev.map(e => `${e.vendor}\u0000${e.product}`)), seen = new Set();
  for (const r of m.rules || []) {
    const key = `${r.vendor}\u0000${r.product}`;
    if (typeof r.vendor !== 'string' || !r.vendor || typeof r.product !== 'string' || !r.product) fail('a rule without a vendor and a product');
    if (!classes.has(r.class)) fail(`unknown class ${JSON.stringify(r.class)} for ${r.vendor}`);
    if (typeof r.reason !== 'string' || !r.reason.trim()) fail(`a rule without a reason: ${r.vendor} ${r.product}`);
    if (typeof r.evidence !== 'string' || !r.evidence.trim()) fail(`a rule without evidence: ${r.vendor} ${r.product}`);
    if (seen.has(key)) fail(`a rule listed twice: ${r.vendor} ${r.product}`); seen.add(key);
    if (!vendors.has(r.vendor)) fail(`no CVE on KEV now for vendor ${r.vendor}: the rule is stale`);
    if (r.product !== '*' && !pairs.has(key)) fail(`no CVE on KEV now for ${r.vendor} ${r.product}: the rule is stale`);
  }
  return classes;
}

// a rule for the vendor and product beats one for the whole vendor
export function classify(m, kev) {
  const exact = new Map(), wide = new Map();
  for (const r of m.rules) (r.product === '*' ? wide : exact).set(r.product === '*' ? r.vendor : `${r.vendor}\u0000${r.product}`, r.class);
  const counts = Object.fromEntries(m.classes.map(c => [c.id, 0])); let none = 0; const byRule = new Map();
  for (const e of kev) {
    const k = `${e.vendor}\u0000${e.product}`, c = exact.get(k) ?? wide.get(e.vendor);
    if (c) { counts[c]++; const rk = exact.has(k) ? k : `${e.vendor}\u0000*`; byRule.set(rk, (byRule.get(rk) || 0) + 1); } else none++;
  }
  return { counts, none, byRule };
}

export function writeSectors(esc) {
  const file = 'src/api/v1/sectors/mapping.json';
  if (!existsSync(file)) return null;
  const m = JSON.parse(readFileSync(file, 'utf8')), kev = loadKev(), classes = check(m, kev), { counts, none, byRule } = classify(m, kev);
  const prods = new Map(); for (const v of new Set(kev.map(e => e.vendor))) prods.set(v, new Set(kev.filter(e => e.vendor === v).map(e => e.product)).size);
  const classedV = new Set(m.rules.filter(r => r.product === '*').map(r => r.vendor)), exactK = new Set(m.rules.filter(r => r.product !== '*').map(r => `${r.vendor}\u0000${r.product}`)), uc = new Map();
  for (const e of kev) if (!classedV.has(e.vendor) && !exactK.has(`${e.vendor}\u0000${e.product}`)) uc.set(e.vendor, (uc.get(e.vendor) || 0) + 1);
  const unclassed = [...uc].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 5).map(([v, n]) => `${v} ${n}`).join(', ');
  const idx = JSON.parse(readFileSync('src/api/v1/cve/index.json', 'utf8')), read = String((idx.reads && idx.reads.kev || []).at(-1) || '');
  const total = kev.length, pct = n => total ? (100 * n / total).toFixed(1) : '0.0';
  const out = { notice: m.notice, status: m.status, source: 'CISA KEV via data.promptugal.news, as kept in /api/v1/cve/', kev_read: read, on_kev_now: total,
    classes: m.classes.map(c => ({ id: c.id, name: c.name, typical_use_not_exposure: c.typical_use, cves: counts[c.id], share_of_kev: Number(pct(counts[c.id])) })), not_classed_yet: none, mapping: '/api/v1/sectors/mapping.json', license: m.license };
  mkdirSync('_site/api/v1/sectors', { recursive: true }); writeFileSync('_site/api/v1/sectors/index.json', JSON.stringify(out, null, 2) + '\n');
  const ex = q => esc('/explore/#' + Object.entries(q).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&'));
  const row = cells => `<tr>${cells.map(c => `<td>${c}</td>`).join('')}</tr>`;
  const ruleRows = m.rules.map(r => row([
    `<a href="${ex(r.product === '*' ? { tab: 'kev', vendor: r.vendor } : { tab: 'kev', vendor: r.vendor, product: r.product })}">${esc(r.vendor)}${r.product === '*' ? '' : ' ' + esc(r.product)}</a>`,
    r.product === '*' ? 'every product' : 'this product only', esc(classes.get(r.class).name), esc(byRule.get(`${r.vendor}\u0000${r.product}`) || 0), esc(r.reason), esc(r.product === '*' && r.class === 'general-it' ? `${prods.get(r.vendor) || 0} distinct products on CISA KEV now` : r.evidence)])).join('');
  mkdirSync('_site/sectors', { recursive: true });
  writeFileSync('_site/sectors/index.html', `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sectors, a proposal: PrompTugal.news Cyber</title>
<meta name="description" content="A proposed mapping of the products on CISA's known-exploited list to classes of use, with its reasons. A proposal, not sector exposure.">
<link rel="icon" href="/assets/brand/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/brand/brand-tokens.css">
<link rel="stylesheet" href="/assets/site.css">
</head>
<body>
<!--@mast:/sectors/-->
<main id="main">
<h1>Sectors: a proposed mapping</h1>
<p class="caveat">${esc(m.notice)}</p>
<p>${esc(m.about)} Prompted by ${esc(m.from)} Made ${esc(m.made)} by ${esc(m.by)}; no person has reviewed it yet.</p>
<h2>What the list holds, by class of product</h2>
<p>Of the ${esc(total)} CVEs on CISA's known-exploited list now (CISA KEV via data.promptugal.news, read ${esc(read)}):</p>
<div class="scroll"><table><tr><th>Class</th><th>Typical use (not exposure)</th><th>CVEs</th><th>Share of the list</th></tr>
${m.classes.map(c => row([esc(c.name), esc(c.typical_use.join(', ')), esc(counts[c.id]), `${esc(pct(counts[c.id]))}%`])).join('\n')}
${row(['Not classed yet', 'unknown', esc(none), `${esc(pct(none))}%`])}
</table></div>
<p>Each CVE is in one row; the shares are of the whole list and are not added up by sector, because a general-IT CVE concerns every sector at once. What this shows so far: ${esc(pct(counts['general-it'] || 0))}% of the list is general-purpose IT from ${esc(m.rules.filter(r => r.class === 'general-it').length)} vendors, ${esc(counts['industrial-control'] || 0)} CVEs are industrial or building control, and ${esc(pct(none))}% is not classed yet (its largest vendors: ${esc(unclassed)}). The list alone says little about any one sector. A sector view needs more than this list: for Portugal, the products public bodies buy (base.gov.pt, not read yet).</p>
<h2>The rules, with their reasons</h2>
<p>${esc(m.precedence)}</p>
<div class="scroll"><table><tr><th>Vendor and product (as named on the list)</th><th>Covers</th><th>Class</th><th>CVEs now</th><th>Reason</th><th>Evidence</th></tr>
${ruleRows}
</table></div>
<h2>JSON</h2>
<p><a href="/api/v1/sectors/index.json">/api/v1/sectors/index.json</a> (the counts) and <a href="/api/v1/sectors/mapping.json">/api/v1/sectors/mapping.json</a> (the rules), CC BY 4.0. To propose a change, <a href="https://github.com/PrompTugal/PrompTugal__News__Cyber/issues/new?title=Sector%20mapping">open an issue</a>.</p>
</main>
<!--@foot-->
</body>
</html>
`);
  return out;
}
