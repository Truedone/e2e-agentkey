// signing through ssh-agent (AGENTKEY_SIGNER=ssh-agent). The role's Ed25519 key is added to the agent on SSH_AUTH_SOCK
// with the confirm constraint, the same one `ssh-add -c` sets, so the agent asks a person (ssh-askpass) before each
// signature, and with remove the key file is deleted once the agent holds it. For an ssh-ed25519 key the agent's
// signature is a plain Ed25519 signature over the bytes it is sent, so a DSSE envelope signed this way verifies with
// the role's public key and kid exactly like one signed from the file. The exchanges follow draft-miller-ssh-agent and
// run in a child process (agent-io.mjs), so these functions are synchronous like the rest of agentkey
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { AgentkeyError, keyPaths, kid, load } from './index.mjs';

const IO = fileURLToPath(new URL('./agent-io.mjs', import.meta.url));
const SSH_AGENT_FAILURE = 5, SSH_AGENT_SUCCESS = 6, SSH2_AGENTC_SIGN_REQUEST = 13, SSH2_AGENT_SIGN_RESPONSE = 14;
const SSH2_AGENTC_ADD_ID_CONSTRAINED = 25, SSH_AGENT_CONSTRAIN_CONFIRM = 2;
// a signature waits for a person to confirm it; two minutes, then the request is given up
const CONFIRM_TIMEOUT_MS = 120_000;

const str = (b) => { const x = Buffer.from(b); const l = Buffer.alloc(4); l.writeUInt32BE(x.length); return Buffer.concat([l, x]); };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const readStr = (b, at) => { const l = b.readUInt32BE(at); return [b.subarray(at + 4, at + 4 + l), at + 4 + l]; };

function socketOf(env) {
  const s = env.SSH_AUTH_SOCK;
  if (!s) throw new AgentkeyError('AGENTKEY_AGENT_UNAVAILABLE', 'AGENTKEY_SIGNER=ssh-agent needs a running ssh-agent: SSH_AUTH_SOCK is not set');
  return s;
}
// one request and its reply, as [type, body after the type byte]
function exchange(socket, request, timeout) {
  const r = spawnSync(process.execPath, [IO], { input: JSON.stringify({ socket, request: request.toString('base64') }), encoding: 'utf8', timeout });
  if (r.error?.code === 'ETIMEDOUT') throw new AgentkeyError('AGENTKEY_AGENT_REFUSED', `ssh-agent gave no answer within ${timeout / 1000} s (a confirmation not given?)`);
  if (r.status === 2) throw new AgentkeyError('AGENTKEY_AGENT_UNAVAILABLE', `no ssh-agent answers on ${socket}: ${r.stderr.trim()}`);
  const reply = Buffer.from(r.stdout || '', 'base64');
  if (!reply.length) throw new AgentkeyError('AGENTKEY_AGENT_REFUSED', 'ssh-agent closed the connection without a reply');
  return [reply[0], reply.subarray(1)];
}
const keyBlob = (publicKey) => Buffer.concat([str('ssh-ed25519'), str(Buffer.from(publicKey, 'base64url'))]);

// adds the role's key to the agent with the confirm constraint; with remove, deletes <role>.key once the agent holds it
// (the .pub stays: it names the key the agent is asked for)
export function agentAdd(role, { env = process.env, remove = false, ...opts } = {}) {
  const socket = socketOf(env);
  const key = load(role, { env, ...opts });
  const jwk = key.privateKey.export({ format: 'jwk' });
  const seed = Buffer.from(jwk.d, 'base64url'), pub = Buffer.from(jwk.x, 'base64url');
  const msg = Buffer.concat([Buffer.from([SSH2_AGENTC_ADD_ID_CONSTRAINED]), str('ssh-ed25519'), str(pub), str(Buffer.concat([seed, pub])),
    str(`agentkey ${role} ${key.kid}`), Buffer.from([SSH_AGENT_CONSTRAIN_CONFIRM])]);
  seed.fill(0);
  const [type] = exchange(socket, msg, 10_000);
  if (type !== SSH_AGENT_SUCCESS) throw new AgentkeyError('AGENTKEY_AGENT_REFUSED', `ssh-agent refused to add the key for role ${role} (reply ${type})`);
  if (remove) fs.rmSync(keyPaths(role, { env, ...opts }).key);
  return { role, kid: key.kid, socket, removed: remove };
}

// a signer for signDSSE whose private key is in the agent: { role, kid, publicKey, signer: 'ssh-agent', sign(bytes) }.
// Each signature is checked against the role's public key before it is returned, so an agent answering with another
// key's signature is refused rather than passed on
export function agentSigner(role, { env = process.env, ...opts } = {}) {
  const socket = socketOf(env);
  const p = keyPaths(role, { env, ...opts });
  let pem;
  try { pem = fs.readFileSync(p.pub, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT') throw new AgentkeyError('AGENTKEY_MISSING', `no public key for role ${role} at ${p.pub}`);
    throw e;
  }
  const pk = crypto.createPublicKey(pem);
  const publicKey = pk.export({ format: 'jwk' }).x;
  const id = kid(publicKey);
  return {
    role, kid: id, publicKey, signer: 'ssh-agent',
    sign(data) {
      const [type, body] = exchange(socket, Buffer.concat([Buffer.from([SSH2_AGENTC_SIGN_REQUEST]), str(keyBlob(publicKey)), str(data), u32(0)]), CONFIRM_TIMEOUT_MS);
      if (type === SSH_AGENT_FAILURE) throw new AgentkeyError('AGENTKEY_AGENT_REFUSED', `ssh-agent refused to sign for role ${role} (${id}): the key is not in the agent, or the confirmation was declined`);
      if (type !== SSH2_AGENT_SIGN_RESPONSE) throw new AgentkeyError('AGENTKEY_AGENT_REFUSED', `ssh-agent answered ${type} to a sign request`);
      const [blob] = readStr(body, 0);
      const [alg, at] = readStr(blob, 0);
      const [sig] = readStr(blob, at);
      if (alg.toString() !== 'ssh-ed25519' || sig.length !== 64 || !crypto.verify(null, data, pk, sig)) {
        throw new AgentkeyError('AGENTKEY_AGENT_REFUSED', `ssh-agent's signature is not role ${role}'s (${id}) Ed25519 signature over the request`);
      }
      return sig;
    },
  };
}
