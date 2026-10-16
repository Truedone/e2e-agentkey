// binding an agent key to its human's SSH signing key. The human signs the agent's public key with
// `ssh-keygen -Y sign -n agentkey`, and a verifier checks that against an allowed_signers file with
// `ssh-keygen -Y verify -n agentkey -I <principal>`: the signature format, the key types and the allowed_signers rules
// are OpenSSH's own (8.0 or later), and nothing of them is reimplemented here
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { AgentkeyError, keyPaths, kid } from './index.mjs';

export const NAMESPACE = 'agentkey';

// what the human signs: the agent public key as the base64url of its 32 raw bytes and a newline, the form
// `agentkey pub <role> --json` gives as publicKey, so the binding does not depend on how the .pub file is written
export function bindingMessage(publicKey) {
  let k = publicKey;
  if (typeof k === 'string' && k.includes('-----BEGIN')) k = crypto.createPublicKey(k);
  if (k instanceof crypto.KeyObject) k = k.export({ format: 'jwk' }).x;
  if (typeof k !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(k)) throw new AgentkeyError('AGENTKEY_INVALID', 'a binding is over an Ed25519 public key: PEM, a KeyObject or its base64url');
  kid(k);
  return Buffer.from(`${k}\n`);
}

function sshKeygen(args, input) {
  try {
    return { ok: true, out: execFileSync('ssh-keygen', args, { input, stdio: ['pipe', 'pipe', 'pipe'] }) };
  } catch (e) {
    if (e.code === 'ENOENT') throw new AgentkeyError('AGENTKEY_SSH_UNAVAILABLE', 'ssh-keygen is not on PATH; binding needs OpenSSH 8.0 or later');
    return { ok: false, status: e.status, err: String(e.stderr ?? e.message).trim() };
  }
}

// signs the role's public key with the SSH key at sshKeyPath (a private key, or a public key whose private half is in
// ssh-agent) and stores the signature as <role>.pub.sshsig and the principal, the identity the human's
// allowed_signers line names, as <role>.pub.principal, both beside <role>.pub
export function bind(role, sshKeyPath, principal, opts = {}) {
  if (typeof principal !== 'string' || !principal || /[\s\x00-\x1f\x7f]/.test(principal)) {
    throw new AgentkeyError('AGENTKEY_PRINCIPAL', 'a principal is the non-empty identity an allowed_signers line names, with no whitespace');
  }
  const p = keyPaths(role, opts);
  let pem;
  try { pem = fs.readFileSync(p.pub, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT') throw new AgentkeyError('AGENTKEY_MISSING', `no key for role ${role} at ${p.pub}; generate(role) creates one`);
    throw e;
  }
  if (!fs.existsSync(sshKeyPath)) throw new AgentkeyError('AGENTKEY_MISSING', `no SSH key at ${sshKeyPath}`);
  const r = sshKeygen(['-Y', 'sign', '-n', NAMESPACE, '-f', sshKeyPath], bindingMessage(pem));
  if (!r.ok) throw new AgentkeyError('AGENTKEY_SSH', `ssh-keygen -Y sign failed (exit ${r.status}): ${r.err}`);
  const sig = `${p.pub}.sshsig`, who = `${p.pub}.principal`;
  fs.writeFileSync(sig, r.out, { mode: 0o644 });
  fs.writeFileSync(who, `${principal}\n`, { mode: 0o644 });
  return { role, kid: kid(pem), principal, sig, principalFile: who };
}

// checks the binding beside the agent public key file pub against an allowed_signers file. status is "bound" when
// ssh-keygen verifies the signature for the principal, "unbound" when there is no <pub>.sshsig, and "invalid" when
// there is one and it does not verify (tampered, another key's, or a principal the file does not allow). The principal
// is the argument when given, else the one stored in <pub>.principal
export function verifyBinding(pub, allowedSignersPath, principal) {
  let pem;
  try { pem = fs.readFileSync(pub, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT') throw new AgentkeyError('AGENTKEY_MISSING', `no public key at ${pub}`);
    throw e;
  }
  const id = kid(pem.trim());
  const sig = `${pub}.sshsig`;
  if (!fs.existsSync(sig)) return { status: 'unbound', kid: id, principal: principal ?? null };
  let who = principal;
  if (who === undefined || who === null) {
    try { who = fs.readFileSync(`${pub}.principal`, 'utf8').trim(); } catch { who = ''; }
    if (!who) return { status: 'invalid', kid: id, principal: null, reason: `${pub}.sshsig has no principal beside it (${pub}.principal) and none was given` };
  }
  if (!fs.existsSync(allowedSignersPath)) throw new AgentkeyError('AGENTKEY_MISSING', `no allowed_signers file at ${allowedSignersPath}`);
  // ssh-keygen -Y verify reads the signature from a file; a copy in a private temporary directory keeps a signature
  // that changes under it from being read twice
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-bind-'));
  try {
    const copy = path.join(tmp, 'sig');
    fs.copyFileSync(sig, copy);
    const r = sshKeygen(['-Y', 'verify', '-n', NAMESPACE, '-I', who, '-f', allowedSignersPath, '-s', copy], bindingMessage(pem.trim()));
    return r.ok ? { status: 'bound', kid: id, principal: who } : { status: 'invalid', kid: id, principal: who, reason: r.err };
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}
