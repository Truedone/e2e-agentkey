// the agentkey command line: init, list, pub, sign, verify and revoke, each with --json. Exit codes: 0 ok, 1 a
// signature failed to verify, 2 an unknown, revoked or expired key or missing input, 3 usage
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { AgentkeyError, home, keyPaths, kid, generate, load, signDSSE, verifyDSSE } from './index.mjs';

export const EXIT = { ok: 0, failed: 1, key: 2, usage: 3 };

const USAGE = `usage: agentkey <command> [--json]
  init [role]                    create the role's key (role defaults to AGENTKEY_ROLE, else "agent")
  list                           the roles that have a key, and the revoked kids
  pub <role>                     the role's public key as SPKI PEM
  sign <role> --type <type>      sign stdin as a DSSE envelope of that payload type, written to stdout
  verify --keys <dir> [--at <t>] verify the DSSE envelope on stdin against the keys in <dir>
  revoke <role>                  move the role's key to revoked/ and list its kid in revoked.txt
exit codes: 0 ok, 1 verification failed, 2 unknown, revoked or expired key or missing input, 3 usage`;

class Exit extends Error {
  constructor(code, reason, message) { super(message); this.exit = code; this.reason = reason; }
}
const usage = (message) => new Exit(EXIT.usage, 'usage', message);

// argv after the command: positionals, and --json, --type, --keys and --at (as "--x v" or "--x=v")
const TAKES = new Set(['type', 'keys', 'at']);
function parse(args) {
  const out = { _: [], json: false };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { out._.push(...args.slice(i + 1)); break; }
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const eq = a.indexOf('=');
    const name = a.slice(2, eq < 0 ? undefined : eq);
    if (name === 'json' && eq < 0) { out.json = true; continue; }
    if (name === 'help' && eq < 0) { out.help = true; continue; }
    if (!TAKES.has(name)) throw usage(`unknown option ${a}`);
    // "--keys --json" is a missing value, not a directory named --json
    const v = eq < 0 ? (args[i + 1]?.startsWith('--') ? undefined : args[++i]) : a.slice(eq + 1);
    if (v === undefined || v === '') throw usage(`--${name} needs a value`);
    out[name] = v;
  }
  return out;
}

// an ISO 8601 date or date-time as epoch ms, or null
const iso = (s) => {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}/.test(s)) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
};

// revoked.txt: one "<kid> <iso date>" per line; blank lines and lines starting with "#" are skipped
export function readRevoked(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return new Map(); throw e; }
  const m = new Map();
  for (const line of text.split(/\r?\n/)) {
    const [k, date] = line.trim().split(/\s+/);
    if (!k || k.startsWith('#')) continue;
    if (!m.has(k)) m.set(k, date ?? null);
  }
  return m;
}

// the files under dir with the given suffix, walked depth first in name order; a symbolic link is not followed
function walk(dir, suffix) {
  const found = [];
  const go = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) go(p);
      else if (e.isFile() && e.name.endsWith(suffix)) found.push(p);
    }
  };
  go(dir);
  return found;
}

// the trusted keys in dir: every *.pub (SPKI PEM, or the base64url of the 32 raw bytes) and every *.json key record
// { publicKey, not_after? } under it, and the revoked kids in dir/revoked.txt. Two files for one kid merge, keeping
// the earliest not_after, so a record that limits a key is never shadowed by a .pub without one
export function trustDir(dir) {
  let st;
  try { st = fs.statSync(dir); } catch { throw new Exit(EXIT.key, 'keys', `no keys directory at ${dir}`); }
  if (!st.isDirectory()) throw new Exit(EXIT.key, 'keys', `${dir} is not a directory`);
  const keys = new Map();
  const add = (file, publicKey, notAfter) => {
    let id;
    try { id = kid(publicKey); } catch (e) { throw new Exit(EXIT.key, 'keys', `${file}: ${e.message}`); }
    const prev = keys.get(id);
    const na = [prev?.notAfter, notAfter].filter((x) => x !== undefined && x !== null);
    keys.set(id, { publicKey: prev?.publicKey ?? publicKey, notAfter: na.length ? Math.min(...na) : null, files: [...(prev?.files ?? []), file] });
  };
  for (const f of walk(dir, '.pub')) add(f, fs.readFileSync(f, 'utf8').trim(), null);
  for (const f of walk(dir, '.json')) {
    let rec;
    try { rec = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { throw new Exit(EXIT.key, 'keys', `${f} is not JSON: ${e.message}`); }
    if (!rec || typeof rec !== 'object' || !('publicKey' in rec)) throw new Exit(EXIT.key, 'keys', `${f} is not a key record: a key record is { "publicKey": ..., "not_after"?: "<iso date>" }`);
    let na = null;
    if (rec.not_after !== undefined && rec.not_after !== null) {
      na = iso(rec.not_after);
      if (na === null) throw new Exit(EXIT.key, 'keys', `${f}: not_after ${JSON.stringify(rec.not_after)} is not an ISO 8601 date`);
    }
    add(f, rec.publicKey, na);
    if (rec.kid !== undefined && rec.kid !== kid(rec.publicKey)) throw new Exit(EXIT.key, 'keys', `${f}: kid ${rec.kid} does not match its publicKey (${kid(rec.publicKey)})`);
  }
  return { keys, revoked: readRevoked(path.join(dir, 'revoked.txt')) };
}

// verifyDSSE against a trust directory, then each kid it verified classed by the directory: revoked when revoked.txt
// lists it, expired when its record's not_after is before `at`. A signature whose keyid is revoked and whose key is no
// longer in the directory is counted as revoked rather than unknown. The reason, in order: failed (a known key did not
// verify its signature), revoked, expired (a verified signature from such a key), verified, and then revoked (only a
// revoked kid's signature, with no key to check it) or unknown
export function verifyWith(envelope, trust, at = Date.now()) {
  const ring = [...trust.keys.values()].map((k) => k.publicKey);
  const r = verifyDSSE(envelope, ring);
  const revoked = r.verified.filter((k) => trust.revoked.has(k));
  const expired = r.verified.filter((k) => !trust.revoked.has(k) && trust.keys.get(k)?.notAfter != null && at > trust.keys.get(k).notAfter);
  const good = r.verified.filter((k) => !revoked.includes(k) && !expired.includes(k));
  const revokedUnknown = r.unknown.filter((k) => k !== null && trust.revoked.has(k));
  let reason, code;
  if (r.failed.length) [reason, code] = ['failed', EXIT.failed];
  else if (revoked.length) [reason, code] = ['revoked', EXIT.key];
  else if (expired.length) [reason, code] = ['expired', EXIT.key];
  else if (good.length) [reason, code] = ['verified', EXIT.ok];
  else if (revokedUnknown.length) [reason, code] = ['revoked', EXIT.key];
  else [reason, code] = ['unknown', EXIT.key];
  return {
    ok: code === EXIT.ok, reason, exit: code, verified: good, revoked: [...revoked, ...revokedUnknown], expired,
    unknown: r.unknown.filter((k) => !revokedUnknown.includes(k)), failed: r.failed, payloadType: r.payloadType, payload: r.payload,
  };
}

const readStdin = (io) => {
  if (io.stdin !== undefined) return Buffer.from(io.stdin);
  try { return fs.readFileSync(0); } catch (e) { if (e.code === 'EAGAIN' || e.code === 'EOF') return Buffer.alloc(0); throw e; }
};

// the roles that have a key under <home>/keys, with the kid of each .pub; on win32 a %XX in a name is decoded back
function listKeys(h, platform) {
  const dir = path.join(h, 'keys');
  if (!fs.existsSync(dir)) return [];
  return walk(dir, '.key').map((f) => {
    let role = path.relative(dir, f).slice(0, -'.key'.length).split(path.sep).join('/');
    if (platform === 'win32') role = role.replace(/%([0-9A-F]{2})/g, (_, x) => String.fromCharCode(parseInt(x, 16)));
    const pub = `${f.slice(0, -'.key'.length)}.pub`;
    let id = null;
    try { id = kid(fs.readFileSync(pub, 'utf8')); } catch { /* a key without a readable .pub is listed with kid null */ }
    return { role, kid: id };
  });
}

const commands = {
  init(a, ctx) {
    if (a._.length > 1) throw usage('init takes at most one role');
    const role = a._[0] ?? ctx.env.AGENTKEY_ROLE ?? 'agent';
    try {
      const g = generate(role, ctx.opts);
      return { result: { ok: true, role, kid: g.kid, publicKey: g.publicKey, created: true }, text: `${g.kid} ${role} created` };
    } catch (e) {
      if (e.code !== 'AGENTKEY_EXISTS') throw e;
      const l = load(role, ctx.opts);
      return { result: { ok: true, role, kid: l.kid, publicKey: l.publicKey, created: false }, text: `${l.kid} ${role} exists` };
    }
  },
  list(a, ctx) {
    if (a._.length) throw usage('list takes no arguments');
    const h = ctx.opts.home ?? home({ env: ctx.env });
    const keys = listKeys(h, ctx.platform);
    const revoked = [...readRevoked(path.join(h, 'keys', 'revoked.txt'))].map(([k, date]) => ({ kid: k, date }));
    const text = [...keys.map((k) => `${k.kid ?? '-'} ${k.role}`), ...revoked.map((r) => `${r.kid} revoked ${r.date ?? ''}`.trimEnd())].join('\n');
    return { result: { ok: true, keys, revoked }, text };
  },
  pub(a, ctx) {
    if (a._.length !== 1) throw usage('pub takes one role');
    const role = a._[0];
    const p = keyPaths(role, ctx.opts);
    let pem;
    try { pem = fs.readFileSync(p.pub, 'utf8'); } catch (e) {
      if (e.code === 'ENOENT') throw new Exit(EXIT.key, 'missing', `no public key for role ${role} at ${p.pub}`);
      throw e;
    }
    const pk = crypto.createPublicKey(pem);
    return { result: { ok: true, role, kid: kid(pk), publicKey: pk.export({ format: 'jwk' }).x, pem }, text: pem.trimEnd() };
  },
  sign(a, ctx) {
    if (a._.length !== 1) throw usage('sign takes one role');
    if (!a.type) throw usage('sign needs --type <payloadType>');
    const key = load(a._[0], ctx.opts);
    const payload = readStdin(ctx.io);
    if (!payload.length) throw new Exit(EXIT.key, 'input', 'sign reads the payload from stdin, and stdin was empty');
    const envelope = signDSSE(a.type, payload, key);
    return { result: { ok: true, role: key.role, kid: key.kid, envelope }, text: JSON.stringify(envelope) };
  },
  verify(a, ctx) {
    if (a._.length) throw usage('verify reads the envelope from stdin and takes no arguments');
    if (!a.keys) throw usage('verify needs --keys <dir>');
    let at = Date.now();
    if (a.at !== undefined) { at = iso(a.at); if (at === null) throw usage(`--at ${a.at} is not an ISO 8601 date`); }
    const input = readStdin(ctx.io);
    if (!input.length) throw new Exit(EXIT.key, 'input', 'verify reads a DSSE envelope from stdin, and stdin was empty');
    let envelope;
    try { envelope = JSON.parse(input.toString('utf8')); } catch (e) { throw new Exit(EXIT.key, 'input', `stdin is not JSON: ${e.message}`); }
    if (envelope && typeof envelope === 'object' && envelope.envelope && !('payloadType' in envelope)) envelope = envelope.envelope;   // the output of sign --json
    const r = verifyWith(envelope, trustDir(a.keys), at);
    const kids = { verified: r.verified, revoked: r.revoked, expired: r.expired, failed: r.failed, unknown: r.unknown };
    const text = r.reason === 'verified' ? `verified ${r.verified.join(' ')}` : `${r.reason} ${(kids[r.reason] ?? []).map((k) => k ?? '(no keyid)').join(' ')}`.trimEnd();
    return { exit: r.exit, result: { ok: r.ok, reason: r.reason, ...kids, payloadType: r.payloadType, payload: r.payload.toString('base64') }, text };
  },
  // the kid is listed in revoked.txt (and synced to disk) before the key moves, so a move that fails leaves the kid
  // revoked; the files go to <home>/revoked/<kid>.key and .pub, which a later key for the same role never collides with
  revoke(a, ctx) {
    if (a._.length !== 1) throw usage('revoke takes one role');
    const role = a._[0];
    const p = keyPaths(role, ctx.opts);
    const h = ctx.opts.home ?? home({ env: ctx.env });
    let id;
    try { id = kid(fs.readFileSync(p.pub, 'utf8')); } catch (e) {
      if (e.code === 'ENOENT') throw new Exit(EXIT.key, 'missing', `no key for role ${role} at ${p.pub}`);
      throw e;
    }
    const date = new Date(ctx.now ?? Date.now()).toISOString();
    const list = path.join(h, 'keys', 'revoked.txt');
    const fd = fs.openSync(list, 'a', 0o644);
    try { fs.writeSync(fd, `${id} ${date}\n`); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    const dir = path.join(h, 'revoked');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    for (const [from, ext] of [[p.key, 'key'], [p.pub, 'pub']]) {
      const to = path.join(dir, `${id}.${ext}`);
      if (fs.existsSync(to)) throw new Exit(EXIT.key, 'exists', `${to} already exists; ${from} was left in place`);
      if (fs.existsSync(from)) fs.renameSync(from, to);
    }
    return { result: { ok: true, role, kid: id, date, revokedList: list }, text: `${id} ${role} revoked ${date}` };
  },
};

// runs one command line; returns the exit code. io: { stdin?, stdout(text), stderr(text) }; opts reach generate and
// load (home, platform). Errors are written to stderr, or with --json as { ok: false, reason, error } on stdout
export function run(argv, { io = {}, env = process.env, opts = {}, now } = {}) {
  const out = io.stdout ?? ((s) => process.stdout.write(s));
  const err = io.stderr ?? ((s) => process.stderr.write(s));
  const [cmd, ...rest] = argv;
  let a = { json: rest.includes('--json') || cmd === '--json' };
  try {
    if (!cmd || cmd === '--help' || cmd === 'help') { out(`${USAGE}\n`); return cmd ? EXIT.ok : EXIT.usage; }
    if (!Object.hasOwn(commands, cmd)) throw usage(`unknown command ${cmd}`);
    a = parse(rest);
    if (a.help) { out(`${USAGE}\n`); return EXIT.ok; }
    const ctx = { env, io, now, platform: opts.platform ?? process.platform, opts: { env, ...opts } };
    const r = commands[cmd](a, ctx);
    out(a.json ? `${JSON.stringify(r.result)}\n` : (r.text ? `${r.text}\n` : ''));
    return r.exit ?? EXIT.ok;
  } catch (e) {
    // any other error (a file it cannot read, say) exits 2 as well, never 1, which means only a failed signature
    let code = e instanceof Exit ? e.exit : EXIT.key, reason = e instanceof Exit ? e.reason : 'error';
    if (e instanceof AgentkeyError) {
      reason = { AGENTKEY_MISSING: 'missing', AGENTKEY_ROLE: 'usage', AGENTKEY_INSECURE: 'insecure', AGENTKEY_INVALID: 'invalid' }[e.code] ?? e.code;
      if (e.code === 'AGENTKEY_ROLE') code = EXIT.usage;
    }
    if (a.json) out(`${JSON.stringify({ ok: false, reason, error: e.message })}\n`);
    else err(`agentkey: ${e.message}${code === EXIT.usage ? `\n${USAGE}` : ''}\n`);
    return code;
  }
}
