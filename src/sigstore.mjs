// keyless signing with Sigstore: a short-lived Fulcio certificate for the CI job's OIDC identity signs the DSSE
// envelope, and Rekor records it. @sigstore/sign is an optional peer dependency, loaded on the first call, so a plain
// install of agentkey fetches no Sigstore package and the rest of agentkey never needs it; without it signKeyless throws
// AGENTKEY_SIGSTORE_UNAVAILABLE (npm install @sigstore/sign@3.1.0 adds it)
import { AgentkeyError } from './index.mjs';

const MISSING = new Set(['ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND']);
async function optional(name) {
  // @sigstore/* are CommonJS: the namespace's default is the exports object, whose names may not all be lifted
  let m;
  try { m = await import(name); } catch (e) {
    if (MISSING.has(e?.code)) throw new AgentkeyError('AGENTKEY_SIGSTORE_UNAVAILABLE', `keyless signing needs ${name}, which is not installed: it comes with @sigstore/sign, an optional peer dependency of agentkey (npm install @sigstore/sign@3.1.0)`);
    throw e;
  }
  return m.default && typeof m.default === 'object' ? { ...m.default, ...m } : m;
}

// the identity token: opts.identityToken when given; else, through @sigstore/sign's CIContextProvider, the GitHub
// Actions OIDC token (a job with id-token: write) or SIGSTORE_ID_TOKEN on any other CI. The audience is "sigstore".
// It is read before anything is sent, so a job with no identity fails here rather than inside the Fulcio request
async function identityToken(sign, token) {
  if (token !== undefined) {
    if (typeof token !== 'string' || !token) throw new AgentkeyError('AGENTKEY_INVALID', 'identityToken is a non-empty string');
    return token;
  }
  try { return await new sign.CIContextProvider('sigstore').getToken(); } catch {
    throw new AgentkeyError('AGENTKEY_SIGSTORE_NO_TOKEN', 'no identity token: run in a GitHub Actions job with id-token: write, set SIGSTORE_ID_TOKEN, or pass identityToken');
  }
}

// signs payload as a DSSE envelope of payloadType with a Fulcio certificate and records it in Rekor. Returns
// { envelope, bundle }: envelope is the DSSE envelope ({ payloadType, payload, signatures }), and bundle is the
// Sigstore bundle (v0.3 JSON) that carries the same envelope with its verification material, the certificate and the
// Rekor entry, which `cosign verify-blob-attestation --bundle` checks. fulcioURL and rekorURL default to the public
// Sigstore instance; a signature there is public, the certificate naming the identity that signed
export async function signKeyless(payloadType, payload, opts = {}) {
  if (typeof payloadType !== 'string' || !payloadType) throw new AgentkeyError('AGENTKEY_INVALID', 'payloadType is a non-empty string');
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload instanceof Uint8Array ? Buffer.from(payload) : null;
  if (!data) throw new AgentkeyError('AGENTKEY_INVALID', 'payload is a string or bytes');
  const sign = await optional('@sigstore/sign');
  const { bundleToJSON } = await optional('@sigstore/bundle');
  const token = await identityToken(sign, opts.identityToken);
  const signer = new sign.FulcioSigner({ identityProvider: { getToken: async () => token }, fulcioBaseURL: opts.fulcioURL ?? sign.DEFAULT_FULCIO_URL });
  const witness = new sign.RekorWitness({ rekorBaseURL: opts.rekorURL ?? sign.DEFAULT_REKOR_URL, entryType: 'dsse' });
  const bundle = bundleToJSON(await new sign.DSSEBundleBuilder({ signer, witnesses: [witness] }).create({ data, type: payloadType }));
  return { envelope: bundle.dsseEnvelope, bundle };
}
