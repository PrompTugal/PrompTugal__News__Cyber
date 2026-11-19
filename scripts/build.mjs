// Build: copy src/ to _site/, put in the shared masthead, sites rail and footer, write a home page
// per source from src/api/v1/sources/index.json, stamp the version, write version.json.
// SITE_VERSION is set by CI only (v0.1.N); a local build says "dev".
// cyber.b@PrompTugal.dinis, 2026-11-18: partials and source pages added. Every value written into a page
// passes through esc(); a URL must be https:// or it is dropped (AppSec: no javascript: or data: links).
import { cpSync, rmSync, readdirSync, readFileSync, writeFileSync, statSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { sitesBar } from './sites-bar.mjs';
const version = process.env.SITE_VERSION || 'dev';
rmSync('_site', { recursive: true, force: true });
cpSync('src', '_site', { recursive: true });
const walk = d => readdirSync(d).flatMap(f => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const url = u => (/^https:\/\/[^\s"'<>]+$/.test(String(u || '')) ? esc(u) : '');
const REPO = 'https://github.com/PrompTugal/PrompTugal__News__Cyber';

const NAV = [['/', 'Pulse'], ['/explore/', 'Explore'], ['/sources/', 'Sources'], ['/api/', 'API'], ['/how/', 'How'], ['/security/', 'Security']];
const bar = await sitesBar('cyber.promptugal.news');
console.log(`sites bar 1.1.0: from ${bar.from}`);
const mast = cur => `<a class="skip" href="#main">Skip to the content</a>
${bar.html}
<header class="mast">
<div class="mast-in">
<a class="brand" href="/"><picture><source srcset="/assets/brand/promptugal-wordmark-dark.svg" media="(prefers-color-scheme: dark)"><img src="/assets/brand/promptugal-wordmark-light.svg" alt="PrompTugal.news" width="200" height="33"></picture><span class="brand-data">· Cyber</span></a>
<nav aria-label="Main">${NAV.map(([h, t]) => `<a href="${h}"${h === cur ? ' aria-current="page"' : ''}>${t}</a>`).join('')}</nav>
</div>
<div class="mast-meta"><span class="ver">Version __VERSION__</span><span>Weak signals, not an audit</span><span class="pay-chip" title="Only promptugal.news bills (Dinis, 18 November 2026). This site carries no billing.">Free to read · <b>no billing here</b></span></div>
</header>`;
const foot = `<footer class="foot">
<p>Weak signals from public sources, not an audit and not a warning service. Aggregates and totals only: no list of IPs, hosts, devices or exposed services, no victim data, no link to a leak site. To report an incident, go to <a href="https://www.cncs.gov.pt/">CNCS and CERT.PT</a>.</p>
<p>If you publish data shown here and think we should not show it, <a href="${REPO}/issues/new?title=Take-down%20request">open an issue</a> and we take it down while we talk (Dinis Cruz, 18 November 2026).</p>
<p>Licences: what PrompTugal.news makes (these pages, our records, the totals) is <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>; every value from a source stays under that source's licence or terms, linked on its source page and in every JSON file (<code>license</code>).</p>
<p class="foot-obs">Code Apache-2.0. Text CC BY 4.0. <a href="https://promptugal.news/principles/">Principles</a> · <a href="https://promptugal.news/report/">Report a problem</a> · <a href="/security/">Security</a> · <a href="${REPO}">Repository</a> · <a href="https://promptugal.news/">PrompTugal.news</a></p>
</footer>`;

// A home page per source (the pipeline standard: Dinis, 18 Nov 2026, about 16:00 UTC).
const reg = JSON.parse(readFileSync('src/api/v1/sources/index.json', 'utf8'));
for (const s of reg.sources) {
  if (!/^[a-z0-9-]+$/.test(s.id)) throw new Error(`source id not a slug: ${s.id}`);
  const dir = join('_site', 'sources', s.id); mkdirSync(dir, { recursive: true });
  const row = (k, v) => `<tr><td>${k}</td><td>${v}</td></tr>`;
  writeFileSync(join(dir, 'index.html'), `<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(s.name)}: PrompTugal.news Cyber</title>
<meta name="description" content="${esc(s.name)} as a source of cyber.promptugal.news: what we would read, its licence, and its state.">
<link rel="icon" href="/assets/brand/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/brand/brand-tokens.css">
<link rel="stylesheet" href="/assets/site.css">
</head>
<body>
<!--@mast:/sources/-->
<main id="main">
<p><a href="/sources/">Sources</a></p>
<h1>${esc(s.name)}</h1>
<p>${esc(s.what)}</p>
<div class="scroll"><table class="kv">
${row('State', `<b>${esc(s.state)}</b>: ${esc(s.state_note)}`)}
${row('Source', `<a href="${url(s.url)}">${esc(s.url)}</a>`)}
${row('Licence or terms', `<a href="${url(s.license.url)}">${esc(s.license.name)}</a>`)}
${row('In its own words', `<q>${esc(s.license.quote)}</q> (as quoted on data.b@'s register, read ${esc(s.license.read)}${String(s.license.quote).endsWith('...') ? '; cut short there, the full terms are linked above' : ''})`)}
${row('Register entry', `<a href="${url(s.register)}">data.promptugal.news, sources we do not read yet</a>`)}
${row('What we would publish', esc(s.we_publish))}
${row('What we never publish', esc(s.we_never))}
${row('Collected by', esc(s.collected_by))}
${row('JSON', `<a href="/api/v1/sources/index.json">/api/v1/sources/index.json</a> (this source's entry, id <code>${esc(s.id)}</code>)`)}
</table></div>
<h2>History, visualisation and analysis</h2>
<p>None yet. Nothing has been read from this source by the PrompTugal.news team. When data.b@PrompTugal.dinis collects it on data.promptugal.news, this page will show every read (raw, timestamped, kept), the weekly totals we draw from it, and what they say.</p>
</main>
<!--@foot-->
</body>
</html>
`);
}

// The pulse on the home page (<!--@pulse-->), from src/api/v1/pulse/index.json: numbers and our own labels only.
const fmtTime = t => esc(String(t).replace('T', ' ').replace(/:\d\d(\.\d+)?Z$/, ' UTC'));
const shown = p => String(p.total);
function pulseHtml() {
  if (pulse.state !== 'live') return '';
  const kev = pulse.series.find(x => x.id === 'kev-added-weekly');
  const nvd = pulse.series.find(x => x.id === 'nvd-new-24h');
  let h = `<p class="caveat">${esc(pulse.caveat)} The Portugal lens (vendors relevant to Portugal) is not built yet.</p>
<p id="p-live" class="x-status" role="status">Figures as built into this page. Your browser reads the latest files from data.promptugal.news when the page opens.</p>`;
  if (kev) {
    const pts = kev.points.slice(-12);
    const max = Math.max(5, ...pts.map(p => p.total || 0));
    const W = 720, H = 220, bw = W / pts.length;
    const bars = pts.map((p, i) => {
      const x = i * bw + 6, w = bw - 12;
      const v = p.total, bh = Math.max(2, Math.round((v / max) * (H - 50)));
      const label = esc(p.total);
      const bar = `<rect class="${p.partial ? 'b-part' : 'b'}" x="${x}" y="${H - 30 - bh}" width="${w}" height="${bh}"/>`;
      return `${bar}<text class="v" x="${x + w / 2}" y="${H - 36 - bh}" text-anchor="middle">${label}</text><text class="w" x="${x + w / 2}" y="${H - 12}" text-anchor="middle">${esc(p.week.slice(5))}</text>`;
    }).join('');
    h += `<h2>Known exploited, week by week</h2>
<p>${esc(kev.title)}. The last 12 weeks, by the Monday each week starts; the current week is still open and drawn lighter.</p>
<figure class="chart"><svg id="p-kev-svg" data-read="${esc(kev.read_at)}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(kev.title)}: ${esc(pts.map(p => `${p.week} ${shown(p)}`).join('; '))}">${bars}</svg>
<figcaption>Source: ${esc(kev.source)}. Underlying data <a href="${url(kev.source_license.url)}">${esc(kev.source_license.name)}</a>; our totals <a href="${url(kev.license.url)}">${esc(kev.license.name)}</a>. Read <span id="p-kev-read">${fmtTime(kev.read_at)}</span> <span id="p-kev-state"></span>. ${esc(pulse.caveat)}</figcaption></figure>
<div class="scroll"><table id="p-kev-table"><tr><th>Week starting</th><th>Added</th></tr>${pts.slice().reverse().map(p => `<tr><td>${esc(p.week)}${p.partial ? ' (so far)' : ''}</td><td>${esc(shown(p))}</td></tr>`).join('')}</table></div>
<p>Every week since the list began (${esc(kev.points.length)} weeks): <a href="/api/v1/pulse/index.json">/api/v1/pulse/index.json</a>.</p>`;
  }
  if (nvd && nvd.points.length) {
    const p = nvd.points.at(-1);
    h += `<h2>New CVEs, the last 24 hours</h2>
<p>${esc(nvd.title)}. As read at <span id="p-nvd-read" data-read="${esc(p.read_at)}">${fmtTime(p.read_at)}</span> <span id="p-nvd-state"></span>: <b id="p-nvd-total">${esc(shown(p))}</b> new CVEs. Reads overlap (every 6 hours, each covering 24 hours), so they are never added up; each is kept.</p>
<div class="scroll"><table id="p-nvd-table"><tr><th>Severity band (CVSS base)</th><th>New</th></tr>${Object.entries(p.by_band).map(([b, v]) => `<tr><td>${esc(b === 'unscored' ? 'not scored yet' : b.toLowerCase())}</td><td>${esc(shown(v))}</td></tr>`).join('')}</table></div>
<p class="notice">${esc(nvd.notice)}</p>
<p class="caveat">Source: ${esc(nvd.source)} Underlying data: <a href="${url(nvd.source_license.url)}">${esc(nvd.source_license.name)}</a>; our totals <a href="${url(nvd.license.url)}">${esc(nvd.license.name)}</a>. ${esc(pulse.caveat)}</p>`;
  }
  return h;
}

// /preview.svg: the site's own numbers for the sites bar (Dinis, 18 Nov 2026, about 22:00 UTC, PrompTugal__News__Website
// board/guidance/2026-11-18-the-sites-bar.md). Counts come from our own JSON only; every text goes through esc().
const pulse = JSON.parse(readFileSync('src/api/v1/pulse/index.json', 'utf8'));
const count = st => reg.sources.filter(x => x.state.startsWith(st)).length;
const figures = pulse.series.reduce((n, x) => n + x.points.length, 0);
const kevS = pulse.series.find(x => x.id === 'kev-added-weekly'), nvdS = pulse.series.find(x => x.id === 'nvd-new-24h');
const shownT = p => (!p ? '0' : String(p.total));
const lastDone = kevS ? kevS.points.filter(p => !p.partial).at(-1) : null;
const tiles = pulse.state === 'live'
  ? [[shownT(lastDone), 'exploited, added last week'], [shownT(nvdS && nvdS.points.at(-1)), 'new CVEs, last 24 hours'], [String(kevS ? kevS.points.length : 0), 'weeks of history']]
  : [[String(figures), 'figures published'], [String(count('collected')), 'sources collected'], [String(count('on hold')), 'source on hold']];
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 630" width="1200" height="630" role="img" aria-label="PrompTugal.news Cyber, worldwide totals: ${esc(tiles.map(t => t.join(' ')).join(', '))}">
<title>PrompTugal.news Cyber: the pulse of Portugal's cyber posture</title>
<rect width="1200" height="630" fill="#f6f3ec"/><rect width="1200" height="10" fill="#c52830"/>
<text x="64" y="120" font-family="Georgia, serif" font-size="64" fill="#121317">PrompTugal.news <tspan fill="#c52830">Cyber</tspan></text>
<text x="64" y="180" font-family="Arial, sans-serif" font-size="30" fill="#5c5e56">${esc(pulse.state === 'live' ? 'Worldwide totals for now; the Portugal lens comes next.' : 'The pulse of Portugal\'s cyber posture, week by week. Totals only.')}</text>
${tiles.map(([n, l], i) => `<g transform="translate(${64 + i * 370} 240)"><rect width="340" height="220" rx="16" fill="#ece8de" stroke="#d8d4cb" stroke-width="2"/><text x="32" y="130" font-family="Georgia, serif" font-size="110" fill="#121317">${esc(n)}</text><text x="32" y="186" font-family="Arial, sans-serif" font-size="23" fill="#5c5e56">${esc(l)}</text></g>`).join('\n')}
<text x="64" y="530" font-family="Arial, sans-serif" font-size="26" fill="#121317">${esc(pulse.state === 'live' ? 'Worldwide totals from CISA KEV and NVD. Weak signals, not an audit.' : 'No figures yet: waiting for the first collected sources to be read. Weak signals, not an audit.')}</text>
<text x="64" y="580" font-family="monospace" font-size="20" fill="#5c5e56">${esc(`From cyber.promptugal.news/api/v1/, ${pulse.updated} · ${version} · CC BY 4.0`)}</text>
</svg>
`;
writeFileSync('_site/preview-card.svg', svg); // 1200x630, the source of /preview.png (social cards)
// /preview.svg for the sites bar: 320x180, from designer@'s template (design/sites-bar/preview-template.svg.txt, vendored)
const tpl = readFileSync('scripts/vendor/sites-bar-1.1.0/preview-template.svg.txt', 'utf8');
const fill = { site: 'PrompTugal.news Cyber', SITE: 'CYBER', line: pulse.state === 'live' ? 'Worldwide totals from CISA KEV and NVD. Weak signals, not an audit.' : 'No figures yet.', accent: '#c52830',
  n1: tiles[0][0], label1: tiles[0][1], n2: tiles[1][0], label2: tiles[1][1], n3: tiles[2][0], label3: tiles[2][1],
  read_at: `${String(pulse.updated)}`, licence: 'CC BY 4.0' };
writeFileSync('_site/preview.svg', tpl.replace(/\{\{(\w+)\}\}/g, (_, k) => esc(fill[k] ?? '')));

for (const f of walk('_site')) {
  if (!/\.(html|js|css|json|md|txt)$/.test(f)) continue;
  let s = readFileSync(f, 'utf8'); const o = s;
  if (f.endsWith('.html')) s = s.replace('</head>', '<link rel="stylesheet" href="/assets/sites-bar/1.1.0/sites-bar.css">\n<script src="/assets/sites-bar/1.1.0/sites-bar.js" defer></script>\n</head>').replace('<!--@pulse-->', () => pulseHtml()).replace(/<!--@mast:([^>]*)-->/g, (_, cur) => mast(cur)).replaceAll('<!--@foot-->', foot);
  if (s.includes('__VERSION__')) s = s.replaceAll('__VERSION__', version);
  if (s !== o) writeFileSync(f, s);
}
writeFileSync('_site/version.json', JSON.stringify({ version, commit: process.env.GITHUB_SHA || 'local', built: new Date().toISOString() }, null, 2) + '\n');
writeFileSync('_site/.nojekyll', '');
console.log(`built _site/ (${version}, ${reg.sources.length} source pages)`);
