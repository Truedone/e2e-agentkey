// rotation: a role moves to a new key, and the old key vouches for the new one. rotate(role) keeps the old key files
// under <home>/rotated/<old kid>.key and .pub, makes a new key for the role, and signs with the old key a rotation
// statement: { role, old, new, publicKey, date }, a DSSE envelope written to <home>/rotations/<old>-<new>.rotation.dsse.
// A receiver puts that file in its trust directory (anywhere under it): rotationsIn then adds the new key as trusted
// when the statement verifies under a key the directory already trusts and that is not revoked, and gives the old key
// a not_after of the statement's date, so the old key's later signatures are expired. Chains of rotations are
// followed in any order. The statement's payload is what the old key signed, so changing the new kid or key in it
// makes it fail to verify
import fs from 'node:fs';
import path from 'node:path';
import { AgentkeyError, home, keyPaths, kid, generate, load, signDSSE, verifyDSSE } from './index.mjs';

export const ROTATION_TYPE = 'application/vnd.agentkey.rotation+json';
const SUFFIX = '.rotation.dsse';

export function rotate(role, { env = process.env, now = Date.now(), ...opts } = {}) {
  const old = load(role, { env, ...opts });
  const p = keyPaths(role, { env, ...opts });
  const h = opts.home ?? home({ env, platform: opts.platform });
  const keep = path.join(h, 'rotated');
  fs.mkdirSync(keep, { recursive: true, mode: 0o700 });
  const moved = [[p.key, `${old.kid}.key`], [p.pub, `${old.kid}.pub`], [`${p.pub}.sshsig`, `${old.kid}.pub.sshsig`], [`${p.pub}.principal`, `${old.kid}.pub.principal`]];
  for (const [, to] of moved) if (fs.existsSync(path.join(keep, to))) throw new AgentkeyError('AGENTKEY_EXISTS', `${path.join(keep, to)} already exists; nothing was rotated`);
  for (const [from, to] of moved) if (fs.existsSync(from)) fs.renameSync(from, path.join(keep, to));
  let fresh;
  try { fresh = generate(role, { env, ...opts }); } catch (e) {
    for (const [from, to] of moved) if (fs.existsSync(path.join(keep, to))) fs.renameSync(path.join(keep, to), from);   // put the old key back
    throw e;
  }
  const date = new Date(now).toISOString();
  const statement = { role, old: old.kid, new: fresh.kid, publicKey: fresh.publicKey, date };
  const envelope = signDSSE(ROTATION_TYPE, JSON.stringify(statement), old);
  const dir = path.join(h, 'rotations');
  fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  const file = path.join(dir, `${old.kid}-${fresh.kid}${SUFFIX}`);
  fs.writeFileSync(file, `${JSON.stringify(envelope)}\n`, { flag: 'wx', mode: 0o644 });
  return { role, old: old.kid, new: fresh.kid, date, file, kept: keep };
}

// the files under dir ending in .rotation.dsse, in name order; a symbolic link is not followed
function rotationFiles(dir) {
  const out = [];
  const go = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      const f = path.join(d, e.name);
      if (e.isDirectory()) go(f);
      else if (e.isFile() && e.name.endsWith(SUFFIX)) out.push(f);
    }
  };
  go(dir);
  return out;
}

// applies the rotation statements under dir to keys (Map kid -> { publicKey, notAfter, files }) in place; revoked is
// the Map of revoked kids. Returns the statements applied, as { file, old, new, date }. A statement that does not parse,
// is not a rotation, or whose new kid is not its key's kid throws, naming the file; one whose signer is unknown or
// revoked is left unapplied (it vouches for nothing), and a signature that fails under a trusted key throws
export function rotationsIn(dir, keys, revoked) {
  const pending = rotationFiles(dir).map((file) => {
    let envelope, st;
    try { envelope = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { throw new AgentkeyError('AGENTKEY_INVALID', `${file} is not JSON: ${e.message}`); }
    if (envelope?.payloadType !== ROTATION_TYPE) throw new AgentkeyError('AGENTKEY_INVALID', `${file} is not a rotation statement (payloadType ${JSON.stringify(envelope?.payloadType)})`);
    try { st = JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8')); } catch (e) { throw new AgentkeyError('AGENTKEY_INVALID', `${file}: the statement is not JSON: ${e.message}`); }
    if (!st || typeof st.old !== 'string' || typeof st.new !== 'string' || typeof st.date !== 'string' || Number.isNaN(Date.parse(st.date))) {
      throw new AgentkeyError('AGENTKEY_INVALID', `${file}: a rotation statement has old, new, publicKey and an ISO date`);
    }
    if (kid(st.publicKey) !== st.new) throw new AgentkeyError('AGENTKEY_INVALID', `${file}: new kid ${st.new} is not the kid of its publicKey (${kid(st.publicKey)})`);
    return { file, envelope, st };
  });
  const applied = [];
  for (let progress = true; progress;) {   // a chain old -> mid -> new applies in any file order
    progress = false;
    for (const r of pending) {
      if (r.done || !keys.has(r.st.old) || revoked.has(r.st.old)) continue;
      const signer = keys.get(r.st.old);
      const v = verifyDSSE(r.envelope, [signer.publicKey]);
      if (!v.ok) throw new AgentkeyError('AGENTKEY_INVALID', `${r.file}: the rotation statement does not verify under ${r.st.old}`);
      const at = Date.parse(r.st.date);
      signer.notAfter = signer.notAfter == null ? at : Math.min(signer.notAfter, at);
      const prev = keys.get(r.st.new);
      keys.set(r.st.new, { publicKey: prev?.publicKey ?? r.st.publicKey, notAfter: prev?.notAfter ?? null, files: [...(prev?.files ?? []), r.file] });
      r.done = true; progress = true;
      applied.push({ file: r.file, old: r.st.old, new: r.st.new, date: r.st.date });
    }
  }
  return applied;
}
