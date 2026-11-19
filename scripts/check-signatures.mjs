// Every commit is signed by its agent's own key, and names its session (Dinis Cruz, 18 November 2026, about 23:55 UTC,
// in cyber.b@PrompTugal.dinis's session: "every single agent ... should have published its public key on the repo that it
// maintains ... every then commit is signed by that key ... you should also include the session ID").
// Usage: node scripts/check-signatures.mjs <before> <after>   (the pushed range; as check-commits.mjs)
// For each commit in the range (merges included) that descends from the pinned trusted base (TRUSTED_BASE):
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

// The one trusted base, pinned (videos.b@'s finding via conductor.b@, 19 Nov 2026, 14:01 UTC): the commit that added this
// check. Found by its full id, never by searching history, which a crafted orphan with an old date could answer.
const TRUSTED_BASE = 'c8fff24023c597a36a76966af5d585b51944c966';
// a shallow clone hides history (and so orphans and unrelated merges): refuse it (security@'s control 6, 19 Nov 2026)
if (tryGit('rev-parse', '--is-shallow-repository') !== 'false') { console.error('check-signatures: refusing a shallow (or unreadable) clone: fetch the whole history first'); process.exit(1); }
const first = TRUSTED_BASE;
if (tryGit('cat-file', '-e', `${first}^{commit}`) === null) { console.error('check-signatures: the trusted base is not in this clone'); process.exit(1); }
const isAncestor = (a, b) => spawnSync('git', ['merge-base', '--is-ancestor', a, b]).status === 0;
if (!isAncestor(first, after)) { console.error('check-signatures: the pushed history does not descend from the trusted base'); process.exit(1); }
const before = beforeArg && !/^0+$/.test(beforeArg) && tryGit('rev-parse', '--verify', '--quiet', `${beforeArg}^{commit}`);
const added = lines(git('rev-list', ...(before ? [`${before}..${after}`] : [after]))); // merges included: a merge is a commit too
const inScope = new Set([first, ...lines(git('rev-list', '--ancestry-path', `${first}..${after}`))]);

// The allowed signers for a commit come from team/keys.json in its first parent, never from the commit itself, so a
// commit cannot add the key it is signed with (conductor.b@, 19 Nov 2026, relaying signals.b@'s review). A new or rotated
// key is added by a commit signed with a key already listed, or by a person. One bootstrap: the commit that added this
// check is checked against its own tree, because the rule starts there.
const dir = mkdtempSync(join(tmpdir(), 'sigcheck-'));
const signerCache = new Map();
function signersAt(rev) {
  const blob = tryGit('rev-parse', `${rev}:team/keys.json`);
  if (!blob) return { file: null, sessionOf: new Map() };
  if (signerCache.has(blob)) return signerCache.get(blob);
  const keys = JSON.parse(git('cat-file', 'blob', blob)).keys || [];
  const signers = []; const sessionOf = new Map();
  for (const k of keys) {
    if (!k.agent || !k.bundle || !k.bundle.sign || k.status === 'superseded') continue;
    if (!/^[a-z0-9]+(?:[.-][a-z0-9]+)*@[a-z0-9.-]+$/i.test(k.agent)) continue;
    const pem = join(dir, `${blob}-${signers.length}.pem`); writeFileSync(pem, k.bundle.sign);
    const ssh = execFileSync('ssh-keygen', ['-i', '-m', 'PKCS8', '-f', pem], { encoding: 'utf8' }).trim().split(' ').slice(0, 2).join(' ');
    signers.push(`${k.agent} namespaces="git" ${ssh}`);
    if (!sessionOf.has(k.agent)) sessionOf.set(k.agent, new Set());
    if (k.session) sessionOf.get(k.agent).add(k.session);
  }
  const file = join(dir, `${blob}.allowed_signers`); writeFileSync(file, signers.join('\n') + '\n');
  const out = { file, sessionOf }; signerCache.set(blob, out); return out;
}

const errors = []; let checked = 0;
let older = 0;
for (const c of added) {
  if (!inScope.has(c)) {
    // older than the base: fine. Anything else (a merged unrelated history, an orphan) is refused, never skipped.
    if (isAncestor(c, first)) { older++; continue; }
    errors.push(`${c.slice(0, 7)} ${git('log', '-1', '--format=%s', c)}: does not descend from the trusted base`); continue;
  }
  if (c !== first && !lines(git('log', '-1', '--format=%P', c)).join(' ').trim()) { errors.push(`${c.slice(0, 7)} ${git('log', '-1', '--format=%s', c)}: an orphan commit (no parent) can only be the trusted base`); continue; }
  checked++;
  const subject = git('log', '-1', '--format=%s', c);
  const agents = lines(git('log', '-1', '--format=%(trailers:key=Agent,valueonly)', c)).map(s => s.trim());
  const sessions = lines(git('log', '-1', '--format=%(trailers:key=Claude-Session,valueonly)', c)).map(s => s.trim());
  const { file: allowed, sessionOf } = signersAt(c === first ? c : `${c}^1`);
  if (!allowed) { errors.push(`${c.slice(0, 7)} ${subject}: its parent has no team/keys.json`); continue; }
  const v = spawnSync('git', ['-c', 'gpg.format=ssh', '-c', 'gpg.ssh.program=ssh-keygen', '-c', `gpg.ssh.allowedSignersFile=${allowed}`, 'verify-commit', c], { encoding: 'utf8' });
  if (v.status !== 0) { errors.push(`${c.slice(0, 7)} ${subject}: no valid signature by a key in its parent's team/keys.json`); continue; }
  const m = `${v.stdout}\n${v.stderr}`.match(/Good "git" signature for (\S+)/);
  const principal = m ? m[1] : null;
  if (!principal || agents.length !== 1 || agents[0] !== principal) { errors.push(`${c.slice(0, 7)} ${subject}: signed by ${principal || 'unknown'}, Agent: ${agents.join(', ') || 'none'}`); continue; }
  const known = sessionOf.get(principal) || new Set();
  if (sessions.length !== 1 || !known.has(sessions[0])) errors.push(`${c.slice(0, 7)} ${subject}: Claude-Session: trailer missing or not the session published with ${principal}'s key`);
}
rmSync(dir, { recursive: true, force: true });
if (errors.length) { console.error(errors.join('\n')); console.error(`FAILED (${errors.length} of ${checked} commits checked)`); process.exit(1); }
console.log(`OK (${checked} signed commits checked, ${older} older than the check skipped)`);
