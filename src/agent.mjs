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
import { AgentkeyError, keyPaths, load, loadPublic } from './index.mjs';

const IO = fileURLToPath(new URL('./agent-io.mjs', import.meta.url));
const SSH_AGENT_FAILURE = 5, SSH_AGENT_SUCCESS = 6, SSH2_AGENTC_SIGN_REQUEST = 13, SSH2_AGENT_SIGN_RESPONSE = 14;
const SSH2_AGENTC_ADD_ID_CONSTRAINED = 25, SSH_AGENT_CONSTRAIN_CONFIRM = 2;
const SSH2_AGENTC_REQUEST_IDENTITIES = 11, SSH2_AGENT_IDENTITIES_ANSWER = 12;
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
  // the key the agent is asked for: derived from the role's .key while it is on disk, else the .pub, accepted only
  // when the agent holds that key under this role's name (loadPublic refuses a .pub copied from another role)
  const own = loadPublic(role, { env, ...opts, held: agentHeld(role, { env }) });
  const pk = crypto.createPublicKey(own.pem);
  const { publicKey, kid: id } = own;
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

// the check loadPublic makes for a role whose .key was moved into the agent: the agent on SSH_AUTH_SOCK holds the
// key, under the comment agentAdd gave it ("agentkey <role> <kid>"). A key the agent holds for another role is
// AGENTKEY_CONFLICT; a key it does not hold is AGENTKEY_AGENT_REFUSED. Nothing is signed and nothing is asked
export function agentHeld(role, { env = process.env } = {}) {
  return (publicKey, id) => {
    const [type, body] = exchange(socketOf(env), Buffer.from([SSH2_AGENTC_REQUEST_IDENTITIES]), 10_000);
    if (type !== SSH2_AGENT_IDENTITIES_ANSWER) throw new AgentkeyError('AGENTKEY_AGENT_REFUSED', `ssh-agent answered ${type} to a request for its keys`);
    const want = keyBlob(publicKey);
    let at = 4;
    for (let n = body.readUInt32BE(0); n > 0; n--) {
      let blob, comment; [blob, at] = readStr(body, at); [comment, at] = readStr(body, at);
      if (!blob.equals(want)) continue;
      const c = comment.toString('utf8');
      if (c === `agentkey ${role} ${id}`) return true;
      throw new AgentkeyError('AGENTKEY_CONFLICT', `the agent holds ${id} as "${c}", not for role ${role}; the role's .pub names another role's key, and nothing was signed`);
    }
    throw new AgentkeyError('AGENTKEY_AGENT_REFUSED', `ssh-agent does not hold role ${role}'s key ${id} (its .key is not on disk either); agent-add ${role} adds it`);
  };
}
