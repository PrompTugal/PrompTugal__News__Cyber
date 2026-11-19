// Tests for the leak scan's key rules (security@'s ruling, 19 Nov 2026, Website 1acd10498: "give each rule a test").
// Every key-shaped string here is built at run time from parts, so this file does not match the scan itself.
// Each case asserts the reason (the kind), not only that the scan failed. Prints OK or the failing cases and exits 1.
import { scanText } from './leak-scan.mjs';

const D = '-'.repeat(5);
const b64 = n => { let x = ''; const r = (x, y) => Array.from({ length: y - x + 1 }, (_, i) => String.fromCharCode(x + i)).join(''); const a = r(65, 90) + r(97, 122) + r(48, 57) + '+/'; for (let i = 0; i < n; i++) x += a[(i * 37 + 11) % 64]; return x; };
const ssh = (type, body) => `${type} AAAA${body}`;
const kinds = (path, text) => scanText(path, text).map(f => f.kind);
const cases = [];
const expect = (name, path, text, kind, want) => cases.push({ name, ok: kinds(path, text).includes(kind) === want, got: kinds(path, text) });

// 1. Every private key header fails everywhere, team/keys.json included.
for (const h of ['OPENSSH ', 'RSA ', 'EC ', 'DSA ', 'ENCRYPTED ', '']) {
  for (const path of ['README.md', 'team/keys.json']) expect(`private ${h || 'PKCS8 '}header in ${path}`, path, `${D}BEGIN ${h}PRIVATE KEY${D}\nx\n${D}END ${h}PRIVATE KEY${D}`, 'private key block', true);
}
// 2. OpenSSH public keys outside their published field are flagged, whatever their entropy.
for (const t of ['ssh-ed25519', 'ssh-rsa', 'ssh-dss', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com']) {
  expect(`${t} in a page`, '_site/index.html', `<p>${ssh(t, b64(64))}</p>`, 'OpenSSH public key outside its published field', true);
  expect(`${t} low-entropy body`, 'docs/x.md', ssh(t, 'A'.repeat(68)), 'OpenSSH public key outside its published field', true);
  expect(`${t} in keys.json, another field`, 'team/keys.json', `{"note": "${ssh(t, b64(64))}"}`, 'OpenSSH public key outside its published field', true);
  expect(`${t} as ssh_signing.public_key`, 'team/keys.json', `{"ssh_signing": {"public_key": "${ssh(t, b64(64))} cyber.b"}}`, 'OpenSSH public key outside its published field', false);
}
expect('public_key field in another file', 'scripts/x.json', `{"public_key": "${ssh('ssh-ed25519', b64(64))}"}`, 'OpenSSH public key outside its published field', true);
// 3. Plain text naming a key type is not a key.
expect('the word ssh-ed25519 alone', 'docs/x.md', 'We sign with ssh-ed25519 or ecdsa-sha2-nistp256 keys.', 'OpenSSH public key outside its published field', false);
// 4. PEM public keys: allowed in team/keys.json, flagged elsewhere.
const pem = `${D}BEGIN PUBLIC KEY${D}\n${b64(64)}\n${D}END PUBLIC KEY${D}`;
expect('PEM public key in team/keys.json', 'team/keys.json', pem, 'public key outside team/keys', false);
expect('PEM public key elsewhere', 'docs/x.md', pem, 'public key outside team/keys', true);

const bad = cases.filter(c => !c.ok);
if (bad.length) { for (const c of bad) console.error(`FAIL ${c.name}: got [${c.got.join(', ')}]`); console.error(`FAILED (${bad.length} of ${cases.length})`); process.exit(1); }
console.log(`OK (${cases.length} leak-scan cases)`);
