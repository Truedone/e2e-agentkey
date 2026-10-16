// setup: from nothing to a role a receiver can check, in one call. It makes the role's key when there is none, binds
// it to the person's SSH key, and copies the public key, the binding and the person's allowed_signers line into the
// trust directory the receiver reads. Every prerequisite is checked before anything is written, a key or a binding
// that is already there is reused and never replaced, and a run that fails after creating the key removes it again
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AgentkeyError, home, keyPaths, kid, generate } from './index.mjs';
import { NAMESPACE, bind, verifyBinding } from './bind.mjs';

const TIMEOUT_MS = 10_000;

// the principal rule bind applies, checked here first so nothing is written for a principal bind would refuse
const checkPrincipal = (principal) => {
  if (typeof principal !== 'string' || !principal || /[\s\x00-\x1f\x7f]/.test(principal)) {
    throw new AgentkeyError('AGENTKEY_PRINCIPAL', 'a principal is the non-empty identity an allowed_signers line names, with no whitespace');
  }
};

// ssh-keygen with no terminal input and a bound on time; ENOENT means it is not installed
const keygen = (args, input) => {
  const r = spawnSync('ssh-keygen', args, { input: input ?? '', stdio: ['pipe', 'pipe', 'pipe'], timeout: TIMEOUT_MS });
  if (r.error?.code === 'ENOENT') throw new AgentkeyError('AGENTKEY_SSH_UNAVAILABLE', 'ssh-keygen is not on PATH; setup needs OpenSSH 8.0 or later');
  return r;
};

// OpenSSH before 8.0 has no -Y; asked for a check of an empty signature, it answers with an option error instead of a
// signature error
function checkSshKeygen() {
  const r = keygen(['-Y', 'check-novalidate', '-n', NAMESPACE, '-s', os.devNull]);
  if (/unknown option|illegal option|invalid option/i.test(String(r.stderr))) {
    throw new AgentkeyError('AGENTKEY_SSH_UNAVAILABLE', `ssh-keygen on PATH has no -Y (${String(r.stderr).trim().split('\n')[0]}); setup needs OpenSSH 8.0 or later`);
  }
}

// the person's SSH public key line ("<type> <blob>") from <key>.pub, or from the key itself when it is the .pub
function sshPublic(sshKey) {
  const pubFile = sshKey.endsWith('.pub') ? sshKey : `${sshKey}.pub`;
  if (!fs.existsSync(sshKey)) throw new AgentkeyError('AGENTKEY_MISSING', `no SSH key at ${sshKey}; pass --ssh-key <path>, or create one with ssh-keygen -t ed25519`);
  if (!fs.existsSync(pubFile)) throw new AgentkeyError('AGENTKEY_MISSING', `no SSH public key at ${pubFile}; ssh-keygen -y -f ${sshKey} > ${pubFile} writes it`);
  const [type, blob] = fs.readFileSync(pubFile, 'utf8').trim().split(/\s+/);
  if (!type || !blob) throw new AgentkeyError('AGENTKEY_INVALID', `${pubFile} is not an SSH public key line`);
  return { pubFile, type, blob };
}

const canAskOnTerminal = () => {
  try { fs.closeSync(fs.openSync('/dev/tty', 'r')); return true; } catch { return false; }
};

// how the SSH key will sign: with the private file when it has no passphrase, through ssh-agent when the agent holds
// it, on the terminal when there is one to ask the passphrase on. With none of those, ssh-keygen would wait on a prompt
// nobody can answer, so setup refuses and says what to do
function signingKey(sshKey, ssh, env) {
  if (sshKey.endsWith('.pub')) return sshKey;
  const plain = keygen(['-y', '-P', '', '-f', sshKey]);
  if (plain.status === 0) return sshKey;
  // an empty passphrase is refused as "incorrect passphrase"; any other answer is a file ssh-keygen cannot read as a key
  const why = String(plain.stderr).trim();
  if (!/passphrase/i.test(why)) throw new AgentkeyError('AGENTKEY_INVALID', `${sshKey} is not an SSH private key ssh-keygen can read (${why.split('\n')[0] || `exit ${plain.status}`})`);
  if (env.SSH_AUTH_SOCK) {
    const listed = spawnSync('ssh-add', ['-L'], { env, stdio: ['ignore', 'pipe', 'pipe'], timeout: TIMEOUT_MS });
    if (listed.status === 0 && String(listed.stdout).split('\n').some((l) => l.split(/\s+/)[1] === ssh.blob)) return ssh.pubFile;
  }
  if (canAskOnTerminal()) return sshKey;
  throw new AgentkeyError('AGENTKEY_SSH_PASSPHRASE', `the SSH key at ${sshKey} needs its passphrase, and no ssh-agent holds it and there is no terminal to ask on; run ssh-add ${sshKey}, then setup again`);
}

// the nearest existing directory at or above dir must be writable, and dir, when it exists, a directory
function checkWritable(dir) {
  let d = path.resolve(dir);
  if (fs.existsSync(d) && !fs.statSync(d).isDirectory()) throw new AgentkeyError('AGENTKEY_MISSING', `the trust directory ${d} is a file, not a directory`);
  while (!fs.existsSync(d)) d = path.dirname(d);
  try { fs.accessSync(d, fs.constants.W_OK); } catch { throw new AgentkeyError('AGENTKEY_MISSING', `the trust directory ${path.resolve(dir)} cannot be written (${d} is not writable)`); }
}

const same = (file, bytes) => fs.existsSync(file) && fs.readFileSync(file).equals(Buffer.from(bytes));
const quote = (s) => (/^[\w./:@%+=,-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

export function setup(role, { principal, sshKey, trust = 'trust', env = process.env, ...opts } = {}) {
  checkPrincipal(principal);
  const p = keyPaths(role, { env, ...opts });
  const h = opts.home ?? home({ env, platform: opts.platform });
  const key = sshKey ?? path.join(env.HOME || os.homedir(), '.ssh', 'id_ed25519');

  // 1. prerequisites, nothing written yet
  checkSshKeygen();
  const ssh = sshPublic(key);
  const signWith = signingKey(key, ssh, env);
  checkWritable(trust);
  const allowedLine = `${principal} namespaces="${NAMESPACE}" ${ssh.type} ${ssh.blob}\n`;
  const rel = path.relative(path.join(h, 'keys'), p.pub);
  const t = { pub: path.join(trust, rel), sig: path.join(trust, `${rel}.sshsig`), who: path.join(trust, `${rel}.principal`), allowed: path.join(trust, 'allowed_signers') };
  const have = fs.existsSync(p.pub) ? fs.readFileSync(p.pub, 'utf8') : null;
  if (!have && fs.existsSync(t.pub)) {
    throw new AgentkeyError('AGENTKEY_CONFLICT', `${t.pub} holds ${kid(fs.readFileSync(t.pub, 'utf8'))}, a key for role ${role} this machine does not have; it is never replaced`);
  }
  if (have && fs.existsSync(t.pub) && !same(t.pub, have)) {
    throw new AgentkeyError('AGENTKEY_CONFLICT', `${t.pub} holds ${kid(fs.readFileSync(t.pub, 'utf8'))}, not this machine's ${kid(have)} for role ${role}; it is never replaced`);
  }
  if (fs.existsSync(`${p.pub}.sshsig`)) {
    // an existing binding is kept only when it is to this principal and this SSH key
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-setup-'));
    try {
      fs.writeFileSync(path.join(tmp, 'allowed_signers'), allowedLine);
      const b = verifyBinding(p.pub, path.join(tmp, 'allowed_signers'));
      if (b.status !== 'bound' || b.principal !== principal) {
        throw new AgentkeyError('AGENTKEY_CONFLICT', `role ${role} is already bound (${p.pub}.sshsig) to another principal or SSH key than ${principal} with ${ssh.pubFile}; a binding is never replaced`);
      }
    } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  }
  for (const [file, ext] of [[t.sig, '.sshsig'], [t.who, '.principal']]) {
    const mine = `${p.pub}${ext}`;
    if (fs.existsSync(file) && !(fs.existsSync(mine) && same(file, fs.readFileSync(mine)))) {
      throw new AgentkeyError('AGENTKEY_CONFLICT', `${file} is there and is not this machine's binding for role ${role}; it is never replaced`);
    }
  }

  // 2. the key and the binding on this machine; a key made by this run is removed again when a later step fails
  const wrote = [];
  let made = false;
  try {
    let id;
    if (!have) { id = generate(role, { env, ...opts }).kid; made = true; wrote.push(p.key, p.pub); } else id = kid(have);
    if (!fs.existsSync(`${p.pub}.sshsig`)) { bind(role, signWith, principal, { env, ...opts }); wrote.push(`${p.pub}.sshsig`, `${p.pub}.principal`); }

    // 3. the receiver's side: copied only when missing, so a second run writes nothing
    fs.mkdirSync(path.dirname(t.pub), { recursive: true });
    for (const [from, to] of [[p.pub, t.pub], [`${p.pub}.sshsig`, t.sig], [`${p.pub}.principal`, t.who]]) {
      if (!fs.existsSync(to)) { fs.copyFileSync(from, to, fs.constants.COPYFILE_EXCL); wrote.push(to); }
    }
    const allowed = fs.existsSync(t.allowed) ? fs.readFileSync(t.allowed, 'utf8') : '';
    if (!allowed.split('\n').some((l) => `${l}\n` === allowedLine)) {
      fs.writeFileSync(t.allowed, `${allowed && !allowed.endsWith('\n') ? '\n' : ''}${allowedLine}`, { flag: 'a' });
      wrote.push(t.allowed);
    }
    return { role, kid: id, principal, trust: path.resolve(trust), sign: `agentkey sign ${quote(role)} --type application/json < report.json > report.dsse.json`, wrote };
  } catch (e) {
    if (made) for (const f of [p.key, p.pub, `${p.pub}.sshsig`, `${p.pub}.principal`]) fs.rmSync(f, { force: true });
    throw e;
  }
}
