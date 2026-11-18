// Build: copy src/ to _site/, put in the shared masthead, sites rail and footer, write a home page
// per source from src/api/v1/sources/index.json, stamp the version, write version.json.
// SITE_VERSION is set by CI only (v0.1.N); a local build says "dev".
// cyber.b@PrompTugal.dinis, 2026-11-18: partials and source pages added. Every value written into a page
// passes through esc(); a URL must be https:// or it is dropped (AppSec: no javascript: or data: links).
import { cpSync, rmSync, readdirSync, readFileSync, writeFileSync, statSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
const version = process.env.SITE_VERSION || 'dev';
rmSync('_site', { recursive: true, force: true });
cpSync('src', '_site', { recursive: true });
const walk = d => readdirSync(d).flatMap(f => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const url = u => (/^https:\/\/[^\s"'<>]+$/.test(String(u || '')) ? esc(u) : '');
const REPO = 'https://github.com/PrompTugal/PrompTugal__News__Cyber';

const NAV = [['/', 'Pulse'], ['/sources/', 'Sources'], ['/api/', 'API'], ['/how/', 'How'], ['/security/', 'Security']];
const mast = cur => `<a class="skip" href="#main">Skip to the content</a>
<header class="mast">
<div class="mast-in">
<a class="brand" href="/"><picture><source srcset="/assets/brand/promptugal-wordmark-dark.svg" media="(prefers-color-scheme: dark)"><img src="/assets/brand/promptugal-wordmark-light.svg" alt="PrompTugal.news" width="200" height="33"></picture><span class="brand-data">· Cyber</span></a>
<nav aria-label="Main">${NAV.map(([h, t]) => `<a href="${h}"${h === cur ? ' aria-current="page"' : ''}>${t}</a>`).join('')}</nav>
</div>
<div class="mast-meta"><span class="ver">Version __VERSION__</span><span>Weak signals, not an audit</span><a class="pay-chip" href="https://promptugal.news/account/" title="Pay for what you read. This site is not on the reading meter until Dinis decides.">Pay for what you read · <b>free here</b></a></div>
</header>
<nav class="em-net" aria-label="The PrompTugal.news sites"><span>Also from PrompTugal.news</span><a href="https://weather.promptugal.news/">Weather</a><a href="https://civic.promptugal.news/">Civic</a><a href="https://startups.promptugal.news/">Startups</a><a href="https://travel.promptugal.news/">Travel</a><a href="https://data.promptugal.news/">Data</a><a href="https://cyber.promptugal.news/" aria-current="page">Cyber</a></nav>`;
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

for (const f of walk('_site')) {
  if (!/\.(html|js|css|json|md|txt)$/.test(f)) continue;
  let s = readFileSync(f, 'utf8'); const o = s;
  if (f.endsWith('.html')) s = s.replace(/<!--@mast:([^>]*)-->/g, (_, cur) => mast(cur)).replaceAll('<!--@foot-->', foot);
  if (s.includes('__VERSION__')) s = s.replaceAll('__VERSION__', version);
  if (s !== o) writeFileSync(f, s);
}
writeFileSync('_site/version.json', JSON.stringify({ version, commit: process.env.GITHUB_SHA || 'local', built: new Date().toISOString() }, null, 2) + '\n');
writeFileSync('_site/.nojekyll', '');
console.log(`built _site/ (${version}, ${reg.sources.length} source pages)`);
