// Tests for the signature check's trust rules (videos.b@'s finding via conductor.b@, 19 Nov 2026, 14:01 UTC: refuse
// orphans except the pinned base, and never run the checker from the pushed tree). Builds a throwaway repository with a
// throwaway key in a temporary directory, sets gpg.ssh.program there (the machine's global signer would otherwise be
// used), and asserts the reason each case fails. Prints OK or the failing cases and exits 1. Nothing here is a real key.
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync, symlinkSync } from 'node:fs';
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
  // live.b@'s findings (relayed 16:15 UTC)
  expect('the site is downloaded into the runner temp folder, vetted there, then moved; a pushed _site path is refused', /path: \$\{\{ runner\.temp \}\}\/site-in/.test(jobs.leakscan || '') && !/path: _site\n[\s\S]*download/.test(jobs.leakscan || '') && /the pushed tree holds a _site path: refusing/.test(jobs.leakscan || '') && /mv "\$in" _site/.test(jobs.leakscan || ''), jobs.leakscan || '');
  expect('pushed .gitattributes are removed in both check jobs before anything runs', ['verify', 'leakscan'].every(j => /-name \.gitattributes -type f -print -exec rm -f/.test(jobs[j] || '')), 'verify, leakscan');
  expect('the anchor counts only a run whose verify and leakscan jobs passed by name', /\/actions\/runs\/\$\{x\.id\}\/jobs/.test(jobs.verify || '') && /\["verify", "leakscan"\]\.every\(n => jobs\.some\(k => k\.name === n && k\.conclusion === "success"\)\)/.test(jobs.verify || ''), 'verify');
  expect('pushed git attributes are never read in the check jobs (GIT_ATTR_SOURCE = the empty tree, git 2.42 or later enforced)', ['verify', 'leakscan'].every(j => /GIT_ATTR_SOURCE: 4b825dc642cb6eb9a060e54bf8d69288fbee4904/.test(jobs[j] || '') && /older than 2\.42/.test(jobs[j] || '')), 'verify, leakscan');
  // the git version check fails closed: run it, as written, against a stub git printing a good, an old and an unreadable version
  {
    const vstep = (jobs.verify || '').match(/\n( +if \[\[ "\$\(git version\)"[^\n]*\n +if ! \[\[[^\n]*\n)/);
    const vbin = join(dir, 'vbin'); mkdirSync(vbin, { recursive: true });
    const tryv = out => { writeFileSync(join(vbin, 'git'), `#!/bin/sh\necho '${out}'\n`, { mode: 0o755 }); const o = spawnSync('bash', ['-c', vstep ? vstep[1] : 'exit 9'], { encoding: 'utf8', env: { ...process.env, PATH: `${vbin}:${process.env.PATH}` } }); return o.status === 0; };
    expect('the git version check passes 2.56.1, refuses 2.41.0, refuses an unreadable version', !!vstep && tryv('git version 2.56.1') && !tryv('git version 2.41.0') && !tryv('git version banana') && !tryv(''), vstep ? 'ran' : 'no version check found');
  }
  expect('the check, deploy and tag jobs run only on refs/heads/dev', ['verify', 'leakscan', 'deploy', 'tag'].every(j => /github\.ref == 'refs\/heads\/dev'/.test(jobs[j] || '')), 'jobs');
  expect('control 9: symlinks on the checker paths are refused', /git ls-tree "\$ANCHOR" "scripts\/\$f"/.test(jobs.verify || '') && /not a plain file/.test(jobs.verify || ''), 'verify');
  const rel = readFileSync(join(here, 'release.sh'), 'utf8');
  const wf = readFileSync(join(here, '../.github/workflows/pages.yml'), 'utf8');
  // the anchor lookup is Node code inside a single-quoted shell string: run that step's shell up to node -e with a stub
  // node that only syntax-checks the code it is given, so an apostrophe or a typo fails here and not in CI
  {
    const st = wf.match(/name: Find the anchor[\s\S]*?run: \|\n([\s\S]*?)\n      - /);
    const code = st && st[1].split('\n').map(l => l.replace(/^ {10}/, '')).join('\n');
    const bin = join(dir, 'stubbin'); mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, 'node'), `#!/bin/sh\n[ "$1" = "-e" ] || exit 2\nprintf '%s' "$2" > "${join(dir, 'anchor.mjs')}"\nexec ${process.execPath} --check "${join(dir, 'anchor.mjs')}"\n`, { mode: 0o755 });
    const o = code ? spawnSync('bash', ['-c', code], { cwd: repo, encoding: 'utf8', env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, GITHUB_ENV: join(dir, 'anchor-env') } }) : null;
    expect('the anchor lookup step is valid shell and valid JavaScript', !!o && o.status === 0, o ? (o.stdout + o.stderr).slice(0, 300) : 'no anchor step');
  }
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
  // control 10 (security@ ed70bd996): no symlinks, unless the anchor's exceptions list the path and target with a reason
  const link = (name, to) => { rmSync(join(repo, name), { force: true }); symlinkSync(to, join(repo, name)); };
  const exFile = list => writeFileSync(join(repo, 'scripts/symlink-exceptions.json'), JSON.stringify({ exceptions: list }));
  link('pushed-link', 'y.txt'); const pushedLink = commit('a pushed symlink');
  c = ci(full, pushedLink); expect('control 10: a pushed symlink fails', !c.ok && /control 10/.test(c.out) && /"pushed-link"/.test(c.out), c.out);
  git('checkout', '-q', next); exFile([{ path: 'docs-link', target: 'y.txt', reason: 'a test exception' }]); const exAnchor = commit('the exception, listed first');
  link('docs-link', 'y.txt'); const listed = commit('the listed symlink');
  c = ci(exAnchor, listed); expect('control 10: a symlink listed at the anchor passes', c.ok, c.out);
  link('docs-link', '../../etc'); const repointed = commit('the listed symlink, repointed');
  c = ci(exAnchor, repointed); expect('control 10: a listed symlink pointed somewhere else fails', !c.ok && /control 10/.test(c.out), c.out);
  git('checkout', '-q', next); exFile([{ path: 'docs-link', target: 'y.txt', reason: 'listed in the same push' }]); link('docs-link', 'y.txt'); const sameP = commit('a symlink listed only in the pushed tree');
  c = ci(next, sameP); expect('control 10: a symlink listed only in the pushed tree fails', !c.ok && /control 10/.test(c.out) && /this push changes scripts\/symlink-exceptions\.json/.test(c.out), c.out);
  git('checkout', '-q', exAnchor); link('docs-link\nx', 'y.txt'); const nl = commit('a name with a newline after a listed name');
  c = ci(exAnchor, nl); expect('control 10: a name with a newline does not match a listed name', !c.ok && /"docs-link\\nx"/.test(c.out), c.out);
  git('checkout', '-q', next); link('gone-link', 'y.txt'); const added = commit('a symlink added'); rmSync(join(repo, 'gone-link')); const removed = commit('and removed again');
  c = ci(next, removed); expect('control 10: a symlink added and removed inside the range still fails (each commit is checked)', !c.ok && /"gone-link"/.test(c.out) && c.out.includes(added.slice(0, 12)), c.out);
  git('checkout', '-q', next); rmSync(join(repo, 'y.txt')); link('y.txt', 'x'); const typed = commit('a file turned into a symlink');
  c = ci(next, typed); expect('control 10: a file turned into a symlink fails', !c.ok && /"y\.txt"/.test(c.out), c.out);
  git('checkout', '-q', next); mkdirSync(join(repo, '.hidden'), { recursive: true }); link('.hidden/l', '../y.txt'); const hidden = commit('a symlink in a hidden folder');
  c = ci(next, hidden); expect('control 10: a symlink in a hidden folder fails', !c.ok && /"\.hidden\/l"/.test(c.out), c.out);
  expect('control 10: the exceptions are read from the anchor, not the pushed tree', /git cat-file blob "\$ANCHOR:scripts\/symlink-exceptions\.json"/.test(body) && /diff-tree", "-r", "-z"/.test(body) && !/grep -x/.test(body), 'pages.yml');
  git('checkout', '-q', 'main');
} catch (e) { expect('the test repository could be built', false, String(e.stderr || e.message).slice(0, 300)); }
finally { rmSync(dir, { recursive: true, force: true }); }
const bad = cases.filter(c => !c.ok);
if (bad.length) { for (const c of bad) console.error(`FAIL ${c.name}: ${String(c.got).slice(0, 300)}`); console.error(`FAILED (${bad.length} of ${cases.length})`); process.exit(1); }
console.log(`OK (${cases.length} signature-check cases)`);
