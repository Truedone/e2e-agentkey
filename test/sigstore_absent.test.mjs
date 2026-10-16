// AK-05: keyless signing is optional. With @sigstore/sign not installed, signKeyless throws
// AGENTKEY_SIGSTORE_UNAVAILABLE and every other function works; with it installed, the identity token is read before
// anything is sent, and the Fulcio request goes to the URL given
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { signKeyless } from '../src/index.mjs';

const SRC = fileURLToPath(new URL('../src/', import.meta.url));
const scratch = (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-sigstore-'));
  t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  return d;
};

test('without @sigstore/sign installed, signKeyless throws AGENTKEY_SIGSTORE_UNAVAILABLE and nothing else breaks', (t) => {
  // the package's own src/ copied where no node_modules is on the resolution path, so the module is truly absent
  const d = scratch(t);
  fs.cpSync(SRC, path.join(d, 'src'), { recursive: true });
  fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ type: 'module' }));
  const probe = path.join(d, 'probe.mjs');
  fs.writeFileSync(probe, `
    import { createRequire } from 'node:module';
    const ak = await import(${JSON.stringify(pathToFileURL(path.join(d, 'src', 'index.mjs')).href)});
    const out = {};
    try { createRequire(import.meta.url).resolve('@sigstore/sign'); out.resolvable = true; } catch { out.resolvable = false; }
    process.env.AGENTKEY_HOME = ${JSON.stringify(path.join(d, 'home'))};
    const g = ak.generate('claude-code');
    const env = ak.signDSSE('application/vnd.in-toto+json', JSON.stringify(ak.statement([{ name: 'a', digest: { sha256: '00' } }], 'https://example.com/p', {})), ak.load('claude-code'));
    out.verified = ak.verifyDSSE(env, [g.publicKey]).ok;
    out.kid = ak.kid(g.publicKey) === g.kid;
    out.bindingMessage = ak.bindingMessage(g.publicKey).toString() === g.publicKey + '\\n';
    try { await ak.signKeyless('text/plain', 'x', { identityToken: 'not-used' }); out.keyless = 'signed'; } catch (e) { out.keyless = e.code; out.message = e.message; }
    console.log(JSON.stringify(out));
  `);
  const r = spawnSync(process.execPath, [probe], { cwd: d, encoding: 'utf8', env: { ...process.env, NODE_PATH: '' } });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.resolvable, false, 'the probe runs where @sigstore/sign cannot be found');
  assert.deepEqual([out.verified, out.kid, out.bindingMessage], [true, true, true], 'generate, sign, verify, kid and bind still load and work');
  assert.equal(out.keyless, 'AGENTKEY_SIGSTORE_UNAVAILABLE');
  assert.match(out.message, /@sigstore\/sign/);
});

test('with @sigstore/sign installed: no identity token is AGENTKEY_SIGSTORE_NO_TOKEN, before any request', async (t) => {
  const keep = {};
  for (const k of ['SIGSTORE_ID_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN']) { keep[k] = process.env[k]; delete process.env[k]; }
  t.after(() => { for (const [k, v] of Object.entries(keep)) if (v !== undefined) process.env[k] = v; });
  let hits = 0;
  const srv = http.createServer((q, s) => { hits++; s.writeHead(500).end(); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(() => srv.close());
  const url = `http://127.0.0.1:${srv.address().port}`;
  await assert.rejects(signKeyless('text/plain', 'x', { fulcioURL: url, rekorURL: url }), { code: 'AGENTKEY_SIGSTORE_NO_TOKEN' });
  assert.equal(hits, 0, 'nothing was sent');
  await assert.rejects(signKeyless('text/plain', 'x', { identityToken: '' }), { code: 'AGENTKEY_INVALID' });
  await assert.rejects(signKeyless('', 'x', { identityToken: 't' }), { code: 'AGENTKEY_INVALID' });
});

test('with @sigstore/sign installed: the token goes to the Fulcio URL given, and a refusal there fails the signing', async (t) => {
  const seen = [];
  const srv = http.createServer((q, s) => {
    let body = '';
    q.on('data', (c) => { body += c; });
    q.on('end', () => { seen.push({ path: q.url, auth: q.headers.authorization, body }); s.writeHead(401, { 'content-type': 'application/json' }).end('{"code":401,"message":"no"}'); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  t.after(() => srv.close());
  const url = `http://127.0.0.1:${srv.address().port}`;
  // a JWT-shaped token: Fulcio's client reads the subject from it to make its proof of possession
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const token = `${b64({ alg: 'none' })}.${b64({ sub: 'ana@example.com', email: 'ana@example.com', iss: 'https://example.com' })}.sig`;
  await assert.rejects(signKeyless('text/plain', 'x', { identityToken: token, fulcioURL: url, rekorURL: url }));
  assert.ok(seen.length >= 1, 'the request reached the given Fulcio URL');
  assert.match(seen[0].path, /^\/api\/v2\/signingCert/);
  assert.ok(seen[0].auth === `Bearer ${token}` || seen[0].body.includes(token), 'with the identity token');
});
