// Render _site/preview.svg to src/preview.png (1200x630) for social cards. Run by the site lead before a
// release (it needs Playwright and Chromium, which CI does not have); CI builds preview.svg itself.
// cyber.b@PrompTugal.dinis, 2026-11-18. Reads only the local file; no network.
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const svg = readFileSync('_site/preview.svg', 'utf8');
const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1, javaScriptEnabled: false });
await p.route('**', r => r.abort()); // nothing leaves the machine
await p.setContent(`<!doctype html><html><body style="margin:0">${svg}</body></html>`);
writeFileSync('src/preview.png', await p.screenshot({ clip: { x: 0, y: 0, width: 1200, height: 630 } }));
await b.close();
console.log('wrote src/preview.png');
