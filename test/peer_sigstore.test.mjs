// AK-PEER-AC01 (draft, unrun): a plain install of agentkey fetches no Sigstore package, and keyless signing works once
// @sigstore/sign is installed. The package is packed from this checkout, installed into a scratch project with its
// own empty npm user config (never the home one) and --prefer-offline (not --offline: npm skips an optional
// dependency that fails to fetch, so an offline install would leave base looking clean). After @sigstore/sign is
// added, signKeyless with no identity token stops at its token check (src/sigstore.mjs, identityToken) with
// AGENTKEY_SIGSTORE_NO_TOKEN, before anything is sent, on any runner: the child's env carries no token variable
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const TOKEN_ENV = ['SIGSTORE_ID_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN'];

function npm(args, cwd, userconfig, timeout) {
  const env = { ...process.env, NPM_CONFIG_USERCONFIG: userconfig, npm_config_audit: 'false', npm_config_fund: 'false' };
  const r = spawnSync('npm', args, { cwd, env, encoding: 'utf8', timeout });
  assert.equal(r.error?.code, undefined, `npm ${args[0]} did not finish within ${timeout} ms`);
  assert.equal(r.status, 0, `npm ${args.join(' ')}: ${r.stderr}`);
  return r.stdout;
}

test('the manifest declares no dependency or optional dependency, and @sigstore/sign as an optional peer', () => {
  for (const k of ['dependencies', 'optionalDependencies']) assert.equal(Object.keys(pkg[k] ?? {}).length, 0, `${k} is empty`);
  assert.equal(pkg.peerDependencies?.['@sigstore/sign'], '3.1.0');
  assert.equal(pkg.peerDependenciesMeta?.['@sigstore/sign']?.optional, true);
});

test('a plain install fetches no @sigstore package; with @sigstore/sign added, keyless stops at the token check', (t) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agentkey-peer-')); t.after(() => fs.rmSync(d, { recursive: true, force: true }));
  const userconfig = path.join(d, 'npmrc'); fs.writeFileSync(userconfig, '');   // empty: ~/.npmrc is never read
  const packed = JSON.parse(npm(['pack', '--json', '--ignore-scripts', '--pack-destination', d, ROOT], d, userconfig, 120_000))[0].filename;
  const proj = path.join(d, 'proj'); fs.mkdirSync(proj);
  fs.writeFileSync(path.join(proj, 'package.json'), JSON.stringify({ name: 'scratch', version: '1.0.0', type: 'module', private: true }));
  npm(['install', '--prefer-offline', '--ignore-scripts', path.join(d, packed)], proj, userconfig, 300_000);
  assert.ok(fs.existsSync(path.join(proj, 'node_modules/@optitransfer/agentkey/package.json')), 'agentkey installed');
  assert.equal(fs.existsSync(path.join(proj, 'node_modules/@sigstore')), false, 'no @sigstore package was installed');

  npm(['install', '--prefer-offline', '--ignore-scripts', '@sigstore/sign@3.1.0'], proj, userconfig, 300_000);
  const probe = path.join(proj, 'probe.mjs');
  fs.writeFileSync(probe, `
    const { signKeyless } = await import('@optitransfer/agentkey');
    try { await signKeyless('text/plain', 'x', { fulcioURL: 'http://127.0.0.1:9', rekorURL: 'http://127.0.0.1:9' }); console.log('signed'); }
    catch (e) { console.log(e.code); }
  `);
  const env = { ...process.env }; for (const k of TOKEN_ENV) delete env[k];
  const r = spawnSync(process.execPath, [probe], { cwd: proj, env, encoding: 'utf8', timeout: 60_000 });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), 'AGENTKEY_SIGSTORE_NO_TOKEN', 'keyless loads @sigstore/sign and stops at its token check');
});
