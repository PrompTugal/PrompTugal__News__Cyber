// Every commit is signed by its agent's own key, and names its session (Dinis Cruz, 18 November 2026, about 23:55 UTC,
// in cyber.b@PrompTugal.dinis's session: "every single agent ... should have published its public key on the repo that it
// maintains ... every then commit is signed by that key ... you should also include the session ID").
// Usage: node scripts/check-signatures.mjs <before> <after>   (the pushed range; as check-commits.mjs)
// For each non-merge commit in the range that descends from the commit that added this file:
//   1. it carries an SSH signature (git's, namespace "git") that verifies against a key in team/keys.json;
//   2. the key's agent is the commit's Agent: trailer;
//   3. its Claude-Session: trailer names the session recorded with that key.
// The OpenSSH form of each key is derived from the published PEM (bundle.sign) with ssh-keygen; nothing else is trusted.
// Needs git 2.34+ and ssh-keygen. Prints OK or lists each failing commit and exits 1. History is never rewritten.
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const git = (...a) => execFileSync('git', a, { encoding: 'utf8' }).trim();
const tryGit = (...a) => { try { return git(...a); } catch { return null; } };
const lines = s => (s ? s.split('\n').filter(Boolean) : []);
const [beforeArg, afterArg] = process.argv.slice(2);
const after = afterArg || 'HEAD';

const first = lines(git('log', '--format=%H', '--diff-filter=A', '--reverse', after, '--', 'scripts/check-signatures.mjs'))[0];
if (!first) { console.error('check-signatures: cannot find the commit that added scripts/check-signatures.mjs'); process.exit(1); }
const before = beforeArg && !/^0+$/.test(beforeArg) && tryGit('rev-parse', '--verify', '--quiet', `${beforeArg}^{commit}`);
const added = lines(git('rev-list', '--no-merges', ...(before ? [`${before}..${after}`] : [after])));
const inScope = new Set([first, ...lines(git('rev-list', '--ancestry-path', `${first}..${after}`))]);

// The allowed signers, from the keys published in this repository at the commit being checked's tip.
const dir = mkdtempSync(join(tmpdir(), 'sigcheck-'));
const keys = JSON.parse(git('show', `${after}:team/keys.json`)).keys || [];
const signers = []; const sessionOf = new Map();
for (const k of keys) {
  if (!k.agent || !k.bundle || !k.bundle.sign || k.status === 'superseded') continue;
  if (!/^[a-z0-9]+(?:[.-][a-z0-9]+)*@[a-z0-9.-]+$/i.test(k.agent)) continue;
  const pem = join(dir, `${signers.length}.pem`); writeFileSync(pem, k.bundle.sign);
  const ssh = execFileSync('ssh-keygen', ['-i', '-m', 'PKCS8', '-f', pem], { encoding: 'utf8' }).trim().split(' ').slice(0, 2).join(' ');
  signers.push(`${k.agent} namespaces="git" ${ssh}`);
  if (!sessionOf.has(k.agent)) sessionOf.set(k.agent, new Set());
  if (k.session) sessionOf.get(k.agent).add(k.session);
}
const allowed = join(dir, 'allowed_signers'); writeFileSync(allowed, signers.join('\n') + '\n');

const errors = []; let checked = 0;
for (const c of added) {
  if (!inScope.has(c)) continue;
  checked++;
  const subject = git('log', '-1', '--format=%s', c);
  const agents = lines(git('log', '-1', '--format=%(trailers:key=Agent,valueonly)', c)).map(s => s.trim());
  const sessions = lines(git('log', '-1', '--format=%(trailers:key=Claude-Session,valueonly)', c)).map(s => s.trim());
  const v = spawnSync('git', ['-c', 'gpg.format=ssh', '-c', 'gpg.ssh.program=ssh-keygen', '-c', `gpg.ssh.allowedSignersFile=${allowed}`, 'verify-commit', c], { encoding: 'utf8' });
  if (v.status !== 0) { errors.push(`${c.slice(0, 7)} ${subject}: no valid signature by a key in team/keys.json`); continue; }
  const m = `${v.stdout}\n${v.stderr}`.match(/Good "git" signature for (\S+)/);
  const principal = m ? m[1] : null;
  if (!principal || agents.length !== 1 || agents[0] !== principal) { errors.push(`${c.slice(0, 7)} ${subject}: signed by ${principal || 'unknown'}, Agent: ${agents.join(', ') || 'none'}`); continue; }
  const known = sessionOf.get(principal) || new Set();
  if (sessions.length !== 1 || !known.has(sessions[0])) errors.push(`${c.slice(0, 7)} ${subject}: Claude-Session: trailer missing or not the session published with ${principal}'s key`);
}
rmSync(dir, { recursive: true, force: true });
if (errors.length) { console.error(errors.join('\n')); console.error(`FAILED (${errors.length} of ${checked} commits checked)`); process.exit(1); }
console.log(`OK (${checked} signed commits checked, ${added.length - checked} older than the check skipped)`);
