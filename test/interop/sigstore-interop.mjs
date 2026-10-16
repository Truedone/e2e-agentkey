// signs a fixture in-toto Statement keyless for the sigstore-interop workflow: node test/interop/sigstore-interop.mjs
// <out dir> writes fixture.txt, the Statement whose subject is its SHA-256, and bundle.json, which the workflow then
// checks with cosign verify-blob-attestation. Needs the job's OIDC token (id-token: write)
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { signKeyless, statement } from '../../src/index.mjs';

export const PREDICATE = 'https://github.com/mgillr/agentkey/sigstore-interop/v1';
const out = process.argv[2];
if (!out) { console.error('usage: node test/interop/sigstore-interop.mjs <out dir>'); process.exit(3); }
fs.mkdirSync(out, { recursive: true });
const fixture = Buffer.from(`agentkey sigstore interop fixture ${process.env.GITHUB_RUN_ID ?? 'local'}\n`);
fs.writeFileSync(path.join(out, 'fixture.txt'), fixture);
const st = statement([{ name: 'fixture.txt', digest: { sha256: crypto.createHash('sha256').update(fixture).digest('hex') } }], PREDICATE, { run: process.env.GITHUB_RUN_ID ?? null });
const { envelope, bundle } = await signKeyless('application/vnd.in-toto+json', JSON.stringify(st));
fs.writeFileSync(path.join(out, 'bundle.json'), `${JSON.stringify(bundle)}\n`);
fs.writeFileSync(path.join(out, 'envelope.json'), `${JSON.stringify(envelope)}\n`);
console.log(JSON.stringify({ predicateType: PREDICATE, subject: st.subject, tlogEntries: bundle.verificationMaterial?.tlogEntries?.length ?? 0 }));
