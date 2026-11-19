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
  const rel = readFileSync(join(here, 'release.sh'), 'utf8');
  const wf = readFileSync(join(here, '../.github/workflows/pages.yml'), 'utf8');
  expect('CI refuses when it cannot find the release a push builds on (no fallback to an old checker)', /refusing; a person decides" >&2; exit 1/.test(wf) && !/ref=c8fff24/.test(wf), 'pages.yml');
  expect('CI runs the checker from the last release, not the pushed tree', /git show "\$from:scripts\/check-signatures\.mjs"/.test(wf) && !/^\s*node scripts\/check-signatures\.mjs/m.test(wf), 'pages.yml');
  expect('release.sh runs the checker from origin/dev, not the tree', /git show "origin\/dev:scripts\/check-signatures\.mjs"/.test(rel) && !/^\s*node scripts\/check-signatures\.mjs/m.test(rel), 'release.sh');
} catch (e) { expect('the test repository could be built', false, String(e.stderr || e.message).slice(0, 300)); }
finally { rmSync(dir, { recursive: true, force: true }); }
const bad = cases.filter(c => !c.ok);
if (bad.length) { for (const c of bad) console.error(`FAIL ${c.name}: ${String(c.got).slice(0, 300)}`); console.error(`FAILED (${bad.length} of ${cases.length})`); process.exit(1); }
console.log(`OK (${cases.length} signature-check cases)`);
