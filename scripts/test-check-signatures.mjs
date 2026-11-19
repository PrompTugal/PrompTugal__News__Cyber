// Tests for the signature check's trust rules (videos.b@'s finding via conductor.b@, 19 Nov 2026, 14:01 UTC: refuse
// orphans except the pinned base, and never run the checker from the pushed tree). Builds a throwaway repository with a
// throwaway key in a temporary directory, sets gpg.ssh.program there (the machine's global signer would otherwise be
// used), and asserts the reason each case fails. Prints OK or the failing cases and exits 1. Nothing here is a real key.
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync, spawnSync } from 'node:child_process';

const here = new URL('.', import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), 'sigtest-'));
const repo = join(dir, 'repo'); mkdirSync(repo);
const sh = (cmd, args, opts = {}) => execFileSync(cmd, args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim();
const git = (...a) => sh('git', a);
const AGENT = 'tester@example.test', SESSION = 'https://claude.ai/code/session_TEST';
const cases = []; const expect = (name, ok, got) => cases.push({ name, ok, got });
try {
  sh('ssh-keygen', ['-q', '-t', 'ecdsa', '-b', '256', '-N', '', '-f', join(dir, 'k')], { cwd: dir });
  const pem = sh('ssh-keygen', ['-e', '-m', 'PKCS8', '-f', join(dir, 'k.pub')], { cwd: dir });
  git('init', '-q', '-b', 'main');
  for (const [k, v] of [['user.name', AGENT], ['user.email', AGENT], ['gpg.format', 'ssh'], ['gpg.ssh.program', 'ssh-keygen'], ['user.signingkey', join(dir, 'k')], ['commit.gpgsign', 'false'], ['tag.gpgsign', 'false']]) git('config', k, v);
  const msg = s => `${s}\n\nAgent: ${AGENT}\nClaude-Session: ${SESSION}`;
  const commit = (s, signed = true) => { git('add', '-A'); git('-c', `commit.gpgsign=${signed}`, 'commit', '-q', '--allow-empty', '-m', msg(s)); return git('rev-parse', 'HEAD'); };
  mkdirSync(join(repo, 'team')); writeFileSync(join(repo, 'team/keys.json'), JSON.stringify({ keys: [{ agent: AGENT, session: SESSION, bundle: { sign: pem } }] }));
  const base = commit('base: the key is published');
  // the checker under test, with its pinned base set to this throwaway repository's base
  const src = readFileSync(join(here, 'check-signatures.mjs'), 'utf8');
  if (!/const TRUSTED_BASE = '[0-9a-f]{40}';/.test(src)) throw new Error('check-signatures.mjs has no pinned TRUSTED_BASE');
  const checker = join(dir, 'check-signatures.mjs'); writeFileSync(checker, src.replace(/const TRUSTED_BASE = '[0-9a-f]{40}';/, `const TRUSTED_BASE = '${base}';`));
  const run = (file, from, to) => { const r = spawnSync('node', [file, from, to], { cwd: repo, encoding: 'utf8' }); return { ok: r.status === 0, out: (r.stdout + r.stderr).trim() }; };

  const good = commit('a good signed commit');
  let r = run(checker, base, good); expect('a signed commit with its trailers passes', r.ok, r.out);

  const unsigned = commit('an unsigned commit', false);
  r = run(checker, good, unsigned); expect('an unsigned commit fails for its signature', !r.ok && /no valid signature/.test(r.out), r.out);
  git('reset', '-q', '--hard', good);

  // an orphan with its own keys file, merged in by a signed merge: refused, never skipped
  git('checkout', '-q', '--orphan', 'evil'); git('rm', '-rq', '--cached', '.'); writeFileSync(join(repo, 'team/keys.json'), JSON.stringify({ keys: [{ agent: AGENT, session: SESSION, bundle: { sign: pem } }] }));
  const orphan = commit('an orphan that brings its own keys');
  git('checkout', '-q', 'main'); git('-c', 'commit.gpgsign=true', 'merge', '-q', '--allow-unrelated-histories', '-X', 'ours', '-m', msg('merge the orphan'), 'evil');
  const merged = git('rev-parse', 'HEAD');
  r = run(checker, good, merged); expect('a merged orphan history is refused', !r.ok && /does not descend from the trusted base/.test(r.out) && r.out.includes(orphan.slice(0, 7)), r.out);
  r = run(checker, '', orphan); expect('an orphan pushed alone is refused', !r.ok && /does not descend from the trusted base/.test(r.out), r.out);
  git('reset', '-q', '--hard', good);

  // the checker must run as it stood at the last release: a push that replaces it with "OK" still fails
  mkdirSync(join(repo, 'scripts'), { recursive: true }); writeFileSync(join(repo, 'scripts/check-signatures.mjs'), readFileSync(checker, 'utf8'));
  const release = commit('the last release carries the real checker');
  writeFileSync(join(repo, 'scripts/check-signatures.mjs'), "console.log('OK');\n");
  const push = commit('an unsigned push that replaces the checker', false);
  const pushed = run(join(repo, 'scripts/check-signatures.mjs'), release, push);
  const fromRelease = join(dir, 'from-release.mjs'); writeFileSync(fromRelease, git('show', `${release}:scripts/check-signatures.mjs`) + '\n');
  r = run(fromRelease, release, push);
  expect('the pushed copy would wave it through (why it must not be used)', pushed.ok, pushed.out);
  expect("the last release's copy refuses the push", !r.ok && /no valid signature/.test(r.out), r.out);
  // a shallow clone is refused before anything is checked
  const shallow = join(dir, 'shallow'); execFileSync('git', ['clone', '-q', '--depth', '1', `file://${repo}`, shallow], { stdio: 'ignore' });
  const rs = spawnSync('node', [checker, '', 'HEAD'], { cwd: shallow, encoding: 'utf8' });
  expect('a shallow clone is refused', rs.status !== 0 && /shallow/.test(rs.stdout + rs.stderr), rs.stdout + rs.stderr);
  // an orphan signed with its own key (not the published one) fails
  sh('ssh-keygen', ['-q', '-t', 'ecdsa', '-b', '256', '-N', '', '-f', join(dir, 'k2')], { cwd: dir });
  git('checkout', '-q', '--orphan', 'evil2'); git('rm', '-rq', '--cached', '.');
  writeFileSync(join(repo, 'team/keys.json'), JSON.stringify({ keys: [{ agent: AGENT, session: SESSION, bundle: { sign: sh('ssh-keygen', ['-e', '-m', 'PKCS8', '-f', join(dir, 'k2.pub')], { cwd: dir }) } }] }));
  git('add', '-A'); git('-c', 'commit.gpgsign=true', '-c', `user.signingkey=${join(dir, 'k2')}`, 'commit', '-q', '-m', msg('an orphan signed with its own key'));
  const orphan2 = git('rev-parse', 'HEAD'); git('checkout', '-q', 'main');
  r = run(checker, release, orphan2); expect('an orphan signed with its own key fails', !r.ok && /does not descend from the trusted base/.test(r.out), r.out);
  const wfs = readFileSync(join(here, '../.github/workflows/pages.yml'), 'utf8');
  expect('CI refuses a shallow checkout and fetches the whole history', /is-shallow-repository/.test(wfs) && /fetch-depth: 0/.test(wfs), 'pages.yml');
  // control 9: the checks run in jobs that have run no pushed code; GITHUB_ENV is per job, so a pushed build step that
  // writes it cannot reach them. Split the workflow into its jobs by their two-space headers.
  const jobs = {}; let cur = null;
  // comment lines are dropped first, so no test can be satisfied by a comment (library.b@'s LIB-2026-067)
  for (const line of readFileSync(join(here, '../.github/workflows/pages.yml'), 'utf8').split('\n').filter(l => !/^\s*#/.test(l))) { const m = line.match(/^  ([a-z][a-z0-9_-]*):\s*$/); if (m) { cur = m[1]; jobs[cur] = ''; } else if (cur) jobs[cur] += line + '\n'; }
  const clean = j => !!jobs[j] && !/node scripts\/|npm |npx /.test(jobs[j]) && /GIT_NO_REPLACE_OBJECTS: '1'/.test(jobs[j]) && /NODE_OPTIONS: ''/.test(jobs[j]) && /NODE=\$\(readlink -f "\$\(command -v node\)"\)/.test(jobs[j]);
  expect('control 9: the verify job runs no pushed code, clears NODE_OPTIONS, sets GIT_NO_REPLACE_OBJECTS, uses an absolute node', clean('verify') && /check-signatures\.mjs" "\$TRUSTED_FROM"/.test(jobs.verify) && /check-commits\.mjs" "\$TRUSTED_FROM"/.test(jobs.verify), jobs.verify || 'no verify job');
  expect('control 9: the leak scan job runs no pushed code and takes the site only as data', clean('leakscan') && /download-artifact/.test(jobs.leakscan) && /find _site -type l/.test(jobs.leakscan), jobs.leakscan || 'no leakscan job');
  expect('control 9: a pushed build step writing GITHUB_ENV cannot change the checks (none run in the build job)', !!jobs.build && !/TRUSTED_DIR|check-signatures\.mjs" |check-commits\.mjs" |leak-scan\.mjs"/.test(jobs.build), jobs.build || 'no build job');
  expect('control 9: deploy and tag need verify, build and the leak scan', /needs: \[verify, build, leakscan\]/.test(jobs.deploy || '') && /needs\.verify\.result == 'success'/.test(jobs.tag || '') && /needs\.leakscan\.result == 'success'/.test(jobs.tag || ''), (jobs.deploy || '') + (jobs.tag || ''));
  expect('the deployed bytes are the scanned bytes: Pages is uploaded only by the leak-scan job, after the scan', /upload-pages-artifact/.test(jobs.leakscan || '') && !/upload-pages-artifact/.test(jobs.build || '') && (jobs.leakscan || '').indexOf('leak-scan.mjs"') < (jobs.leakscan || '').indexOf('upload-pages-artifact'), jobs.leakscan || '');
  expect('a pushed change to .gitattributes or the exemptions stops the run', /git diff --quiet "\$ANCHOR" "\$AFTER" -- \.gitattributes/.test(jobs.verify || '') && /commit-exemptions\.json/.test(jobs.verify || ''), 'verify');
  expect('control 9: symlinks on the checker paths are refused', /git ls-tree "\$ANCHOR" "scripts\/\$f"/.test(jobs.verify || '') && /not a plain file/.test(jobs.verify || ''), 'verify');
  const rel = readFileSync(join(here, 'release.sh'), 'utf8');
  const wf = readFileSync(join(here, '../.github/workflows/pages.yml'), 'utf8');
  expect('CI refuses when there is no anchor (no fallback to an old checker)', /no anchor: no successful run of this workflow recorded/.test(wf) && !/ref=c8fff24/.test(wf), 'pages.yml');
  expect('CI finds the anchor from the latest successful push run of this workflow on dev, not a deployment or a tag', /actions\/workflows\/pages\.yml\/runs\?branch=dev&event=push&status=success/.test(wf) && /x\.path === path && x\.head_branch === "dev" && x\.event === "push" && x\.conclusion === "success"/.test(wf) && !/\/deployments/.test(wf), 'pages.yml');
  expect('CI takes every security check from the last release, never the pushed tree', /git show "\$ANCHOR:scripts\/\$f"/.test(wf) && /check-commits\.mjs check-signatures\.mjs leak-scan\.mjs/.test(wf) && !/node scripts\/(check-|leak-scan)/.test(wf), 'pages.yml');
  expect('CI fails when a trusted copy is missing', /trusted copy of \$f is missing at the anchor \$ANCHOR.*exit 1/.test(wf), 'pages.yml');
  expect('release.sh runs every security check from origin/dev, not the tree', /git show "origin\/dev:scripts\/\$f"/.test(rel) && !/node scripts\/(check-|leak-scan)/.test(rel) && /trusted check-commits\.mjs/.test(rel) && /trusted leak-scan\.mjs/.test(rel), 'release.sh');
  // control 8: a commit that deletes the checker and adds an unsigned change is still refused by the trusted copy
  git('checkout', '-q', release); git('rm', '-q', 'scripts/check-signatures.mjs'); writeFileSync(join(repo, 'x.txt'), 'unsigned\n');
  const gone = commit('delete the checker and slip in an unsigned change', false);
  r = run(fromRelease, release, gone); expect('a commit that removes the checker and adds an unsigned change fails', !r.ok && /no valid signature/.test(r.out), r.out);
  git('checkout', '-q', 'main');
  // a backdated orphan (an old author and committer date) is refused: skips are decided by ancestry only
  git('checkout', '-q', '--orphan', 'old'); git('rm', '-rq', '--cached', '.');
  const oldDate = { ...process.env, GIT_AUTHOR_DATE: '2001-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2001-01-01T00:00:00Z' };
  writeFileSync(join(repo, 'old.txt'), 'old\n'); execFileSync('git', ['add', '-A'], { cwd: repo });
  execFileSync('git', ['-c', 'commit.gpgsign=true', 'commit', '-q', '-m', msg('a backdated orphan')], { cwd: repo, env: oldDate });
  const old = git('rev-parse', 'HEAD'); git('checkout', '-q', 'main');
  git('-c', 'commit.gpgsign=true', 'merge', '-q', '--allow-unrelated-histories', '-X', 'ours', '-m', msg('merge the backdated orphan'), 'old');
  r = run(checker, release, git('rev-parse', 'HEAD')); expect('a backdated orphan is refused', !r.ok && /does not descend from the trusted base/.test(r.out) && r.out.includes(old.slice(0, 7)), r.out);
  git('reset', '-q', '--hard', release);
  // the CI step itself, run as written in pages.yml, on this throwaway repository (base swapped for this repo's base)
  const step = wf.match(/name: Take every security check from the anchor's tree[\s\S]*?run: \|\n([\s\S]*?)\n      - name:/);
  if (!step) throw new Error('cannot find the CI trusted-copy step in pages.yml');
  const body = step[1].split('\n').map(l => l.replace(/^ {10}/, '')).join('\n').replace(/base=[0-9a-f]{40}/, `base=${base}`);
  const ci = (before, after) => { const t = join(dir, 'ci'); rmSync(t, { recursive: true, force: true }); mkdirSync(t); const o = spawnSync('bash', ['-euo', 'pipefail', '-c', body], { cwd: repo, encoding: 'utf8', env: { ...process.env, ANCHOR: before, AFTER: after, RUNNER_TEMP: t, GITHUB_ENV: join(t, 'env'), GITHUB_OUTPUT: join(t, 'out') } }); return { ok: o.status === 0, out: (o.stdout + o.stderr).trim() }; };
  git('checkout', '-q', release);
  for (const f of ['check-commits.mjs', 'leak-scan.mjs']) writeFileSync(join(repo, 'scripts', f), readFileSync(join(here, f), 'utf8'));
  const full = commit('a release that carries all three checks');
  writeFileSync(join(repo, 'y.txt'), 'y\n'); const next = commit('a normal next push');
  let c = ci(full, next); expect('CI: a normal push from a release that has the checks finds them', !c.ok ? false : true, c.out);
  c = ci(good, next); expect('CI: a missing copy of the checks at the anchor fails', !c.ok && /trusted copy of check-commits\.mjs is missing/.test(c.out), c.out);
  c = ci(next, full); expect('CI: an anchor that is not an ancestor of AFTER (a force push) fails', !c.ok && /not an ancestor of this push/.test(c.out), c.out);
  c = ci('', next); expect('CI: a missing anchor fails', !c.ok && /no anchor/.test(c.out), c.out);
  c = ci('0000000000000000000000000000000000000000', next); expect('CI: an anchor not in the clone fails', !c.ok && /no anchor/.test(c.out), c.out);
  expect('CI: the trusted-copy step never consults tags', !/describe|refs\/tags|\btag\b/.test(body), 'pages.yml');
  // a dropped run: an unsigned commit pushed between the anchor and the last push is still in A..AFTER and fails
  git('checkout', '-q', next); writeFileSync(join(repo, 'z.txt'), 'dropped\n'); const dropped = commit('an unsigned commit whose run was dropped', false);
  writeFileSync(join(repo, 'z2.txt'), 'later\n'); const later = commit('a later signed push');
  git('tag', 'v0.1.999', dropped); // a pushed tag on the unverified commit: not used
  c = ci(full, later); const tr = c.ok ? run(join(dir, 'ci', 'trusted', 'check-signatures.mjs'), full, later) : c;
  expect('CI: an unsigned commit from a dropped run (between A and the last push) fails', !tr.ok && /no valid signature/.test(tr.out) && tr.out.includes(dropped.slice(0, 7)), tr.out);
  expect('CI: a pushed tag on an unverified commit is not used as the anchor', readFileSync(join(dir, 'ci', 'env'), 'utf8').includes(`TRUSTED_FROM=${full}`), 'env');
  git('checkout', '-q', 'main');
} catch (e) { expect('the test repository could be built', false, String(e.stderr || e.message).slice(0, 300)); }
finally { rmSync(dir, { recursive: true, force: true }); }
const bad = cases.filter(c => !c.ok);
if (bad.length) { for (const c of bad) console.error(`FAIL ${c.name}: ${String(c.got).slice(0, 300)}`); console.error(`FAILED (${bad.length} of ${cases.length})`); process.exit(1); }
console.log(`OK (${cases.length} signature-check cases)`);
