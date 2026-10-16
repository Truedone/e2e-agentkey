// agentkey: one Ed25519 key per agent role on a machine. node:crypto only, no runtime dependencies
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export class AgentkeyError extends Error {
  constructor(code, message) { super(message); this.name = 'AgentkeyError'; this.code = code; }
}

// where keys live: AGENTKEY_HOME when set; on win32 %APPDATA%/agentkey; elsewhere $XDG_CONFIG_HOME/agentkey, where an
// unset or relative XDG_CONFIG_HOME means ~/.config (the XDG base directory rule)
export function home({ env = process.env, platform = process.platform } = {}) {
  if (env.AGENTKEY_HOME) return env.AGENTKEY_HOME;
  if (platform === 'win32') return path.win32.join(env.APPDATA || path.win32.join(os.homedir(), 'AppData', 'Roaming'), 'agentkey');
  const xdg = env.XDG_CONFIG_HOME && path.posix.isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : path.posix.join(os.homedir(), '.config');
  return path.posix.join(xdg, 'agentkey');
}

// <home>/keys/<role>.key and .pub. A "/" in a role is a directory (claude-code/subagent:reviewer); a part that is
// empty, "." or "..", or holds a backslash or a control character is refused, so no role names a file outside keys/.
// On win32 a ":" in a file name opens an alternate data stream, so there the characters Windows does not allow in a
// name, and "%" to keep the mapping one-to-one, are written as %XX; elsewhere the role is the path as it is
const WIN_NAME = /[<>:"|?*%]/g;
export function keyPaths(role, opts = {}) {
  const platform = opts.platform ?? process.platform;
  if (typeof role !== 'string' || !role) throw new AgentkeyError('AGENTKEY_ROLE', 'a role is a non-empty string');
  const parts = role.split('/');
  for (const s of parts) {
    if (!s || s === '.' || s === '..' || /[\\\x00-\x1f\x7f]/.test(s)) {
      throw new AgentkeyError('AGENTKEY_ROLE', `role ${JSON.stringify(role)} cannot name a key file: each "/"-separated part must be non-empty, not "." or "..", with no backslash or control character`);
    }
  }
  const P = platform === 'win32' ? path.win32 : path.posix;
  const names = platform === 'win32' ? parts.map(s => s.replace(WIN_NAME, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())) : parts;
  const base = P.join(opts.home ?? home({ env: opts.env, platform }), 'keys', ...names);
  return { key: `${base}.key`, pub: `${base}.pub` };
}

// the raw 32-byte Ed25519 public key from a KeyObject (public or private), a PEM string, the base64url form hivevault
// stores as a replica key's x, or the 32 bytes themselves
function rawPublicKey(publicKey) {
  let k = publicKey;
  if (typeof k === 'string' && k.includes('-----BEGIN')) k = crypto.createPublicKey(k);
  if (k instanceof crypto.KeyObject) {
    if (k.type === 'private') k = crypto.createPublicKey(k);
    if (k.asymmetricKeyType !== 'ed25519') throw new AgentkeyError('AGENTKEY_INVALID', `not an Ed25519 key: ${k.asymmetricKeyType}`);
    return Buffer.from(k.export({ format: 'jwk' }).x, 'base64url');
  }
  if (typeof k === 'string') {
    if (!/^[A-Za-z0-9_-]{43}$/.test(k)) throw new AgentkeyError('AGENTKEY_INVALID', 'a public key string is PEM or the base64url of 32 bytes');
    return Buffer.from(k, 'base64url');
  }
  if (k instanceof Uint8Array && k.length === 32) return Buffer.from(k);
  throw new AgentkeyError('AGENTKEY_INVALID', 'a public key is a KeyObject, PEM, base64url or 32 bytes');
}

// "k" and the first 16 hex characters of SHA-256 over the raw public key: hivevault's replicaIdForKey
// (server/src/crdt.mjs), so one id names the key in both
export function kid(publicKey) {
  return `k${crypto.createHash('sha256').update(rawPublicKey(publicKey)).digest('hex').slice(0, 16)}`;
}

// creates the role's keypair: the private key as PKCS8 PEM, mode 0600, created exclusively (an existing key is never
// replaced, since a binding or a receipt may name it), and the public key as SPKI PEM beside it
export function generate(role, opts = {}) {
  const p = keyPaths(role, opts);
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.mkdirSync(path.dirname(p.key), { recursive: true, mode: 0o700 });
  let fd;
  try { fd = fs.openSync(p.key, 'wx', 0o600); } catch (e) {
    if (e.code === 'EEXIST') throw new AgentkeyError('AGENTKEY_EXISTS', `a key for role ${role} already exists at ${p.key}; it is never replaced`);
    throw e;
  }
  try {
    fs.fchmodSync(fd, 0o600);   // the umask can only clear bits from 0600, but a key written wider than 0600 must never exist
    fs.writeSync(fd, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    fs.fsyncSync(fd);
  } catch (e) {
    fs.closeSync(fd); fd = undefined; fs.rmSync(p.key, { force: true });
    throw e;
  } finally { if (fd !== undefined) fs.closeSync(fd); }
  fs.writeFileSync(p.pub, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  return { kid: kid(publicKey), publicKey: rawPublicKey(publicKey).toString('base64url') };
}

// the role's key: { role, kid, publicKey (base64url), privateKey (KeyObject) }. Throws AGENTKEY_MISSING when there is
// none, and AGENTKEY_INSECURE for a symbolic link, a non-file or a mode other than 0600. The mode is read from the open
// descriptor, so it is the mode of the bytes read. win32 has no POSIX modes (fstat reports 0666 or 0444); there the
// key is guarded by the user's ACL on %APPDATA%
export function load(role, opts = {}) {
  const p = keyPaths(role, opts);
  const platform = opts.platform ?? process.platform;
  let fd;
  try { fd = fs.openSync(p.key, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0)); } catch (e) {
    if (e.code === 'ENOENT') throw new AgentkeyError('AGENTKEY_MISSING', `no key for role ${role} at ${p.key}; generate(role) creates one`);
    if (e.code === 'ELOOP') throw new AgentkeyError('AGENTKEY_INSECURE', `${p.key} is a symbolic link; a key file is a regular file with mode 0600`);
    throw e;
  }
  let pem;
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new AgentkeyError('AGENTKEY_INSECURE', `${p.key} is not a regular file`);
    const mode = st.mode & 0o777;
    if (platform !== 'win32' && mode !== 0o600) {
      throw new AgentkeyError('AGENTKEY_INSECURE', `${p.key} has mode ${mode.toString(8).padStart(4, '0')}; a key file must be mode 0600 (chmod 600 ${p.key})`);
    }
    pem = fs.readFileSync(fd, 'utf8');
  } finally { fs.closeSync(fd); }
  let privateKey;
  try { privateKey = crypto.createPrivateKey(pem); } catch (e) {
    throw new AgentkeyError('AGENTKEY_INVALID', `${p.key} is not a PKCS8 PEM private key: ${e.message}`);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new AgentkeyError('AGENTKEY_INVALID', `${p.key} holds a ${privateKey.asymmetricKeyType} key, not Ed25519`);
  return { role, kid: kid(privateKey), publicKey: rawPublicKey(privateKey).toString('base64url'), privateKey };
}
