# agentkey

agentkey gives each AI agent role on a machine one Ed25519 key, and signs and verifies DSSE envelopes and in-toto Statements with it. It has no runtime dependencies (`node:crypto` only) and needs Node 22. The key id is `k` followed by the first 16 hex of SHA-256 over the raw public key, the same scheme hivevault uses for replica keys. A key at rest is readable by every process of the user who owns it, so a signature identifies that user's key set for the role, not one agent process. The library is in development: the functions, the CLI and the binding to an SSH signing key land task by task under `proofline.json`.

## Keys

```js
import { generate, load, kid } from '@optitransfer/agentkey';

const { kid: id, publicKey } = generate('claude-code');   // once per role per machine
const key = load('claude-code');                          // { role, kid, publicKey, privateKey }
kid(publicKey) === id;                                    // true
```

- `generate(role)` creates the role's keypair and returns `{ kid, publicKey }`, the public key as the base64url of its 32 raw bytes (the form hivevault stores as a replica key). It never replaces an existing key: a second call throws `AGENTKEY_EXISTS`.
- `load(role)` returns `{ role, kid, publicKey, privateKey }` with `privateKey` a `KeyObject`. It throws `AGENTKEY_MISSING` when the role has no key, and `AGENTKEY_INSECURE` when the key file's mode is not 0600 or the file is a symbolic link.
- `kid(publicKey)` takes a `KeyObject`, a PEM string, the base64url form or the 32 bytes.

A key lives at `$XDG_CONFIG_HOME/agentkey/keys/<role>.key` (PKCS8 PEM, mode 0600), with the public key beside it as `<role>.pub` (SPKI PEM). An unset or relative `XDG_CONFIG_HOME` means `~/.config`. On Windows the home is `%APPDATA%/agentkey`. `AGENTKEY_HOME` overrides either. A role is a string you choose, such as `claude-code`, `codex`, `cursor`, `gemini-cli` or `crewai/<worker>`; each `/` in it is a directory, so `crewai/research:lead` is `keys/crewai/research:lead.key`. A part of a role that is empty, `.` or `..`, or that holds a backslash or a control character is refused (`AGENTKEY_ROLE`). On Windows the characters it does not allow in a file name (`<>:"|?*`), and `%`, are written as `%XX`, because a `:` there opens an alternate data stream.

Windows has no POSIX file modes, so `load` does not check the mode there; the key is protected by the user's access control on `%APPDATA%`.

## Envelopes and Statements

```js
import { load, signDSSE, verifyDSSE, statement } from '@optitransfer/agentkey';

const key = load('claude-code');
const st = statement([{ name: 'app.tgz', digest: { sha256: '...' } }], 'https://example.com/predicate/v1', { ok: true });
const env = signDSSE('application/vnd.in-toto+json', JSON.stringify(st), key);
const r = verifyDSSE(env, [key.publicKey]);   // { ok, verified, unknown, failed, payloadType, payload }
```

- `signDSSE(payloadType, payload, key)` signs the DSSE pre-authentication encoding (`pae`) of the type and the payload with the role's Ed25519 key and returns an envelope with exactly one signature, whose `keyid` is the key's kid. The payload is a string or bytes; the envelope carries it as base64.
- `verifyDSSE(envelope, keys)` checks every signature against the trusted keys, given as Ed25519 public keys in any form `kid` takes, or as `{ kid, publicKey }` for a key of another type (it verifies ECDSA P-256 too, which is what DSSE's own test vector uses). Each signature's kid lands in `verified`, `unknown` (no trusted key has that keyid) or `failed` (a trusted key whose signature does not verify). `ok` is true only when at least one signature verified and none failed: a failed signature for a known key fails the whole result, and is never skipped. `payload` holds the bytes that were verified, decoded once, so use those rather than reading the envelope again. Standard and URL-safe base64 are both accepted.
- `statement(subjects, predicateType, predicate)` returns an in-toto Statement v1, `{ _type: "https://in-toto.io/Statement/v1", subject, predicateType, predicate }`; each subject needs a non-empty `digest` map.

## Command line

```sh
agentkey init claude-code                     # once per role; prints "<kid> claude-code created"
agentkey pub claude-code > trust/claude-code.pub
echo '{"ok":true}' | agentkey sign claude-code --type application/json > env.json
agentkey verify --keys trust < env.json       # "verified <kid>", exit 0
agentkey revoke claude-code                   # the key moves to revoked/, its kid is listed in keys/revoked.txt
```

| Command | Does |
| --- | --- |
| `init [role]` | Creates the role's key. The role defaults to `AGENTKEY_ROLE`, else `agent`. An existing key is reported (`created: false`) and never replaced. |
| `list` | Every role that has a key, with its kid, and the kids in `keys/revoked.txt`. |
| `pub <role>` | The role's public key as SPKI PEM. |
| `sign <role> --type <payloadType>` | Signs stdin and writes the DSSE envelope to stdout. |
| `verify --keys <dir> [--at <date>]` | Verifies the DSSE envelope on stdin against the keys in `<dir>`. |
| `revoke <role>` | Appends `<kid> <ISO date>` to `keys/revoked.txt`, then moves the key and its `.pub` to `revoked/<kid>.key` and `.pub`. |

Every command takes `--json` and then writes one JSON object to stdout, errors included (`{ "ok": false, "reason", "error" }`). The exit codes are:

| Code | Meaning |
| --- | --- |
| 0 | ok |
| 1 | verification failed: a trusted key's signature does not verify |
| 2 | an unknown, revoked or expired key, or missing input (empty stdin, no key for the role, an unreadable keys directory) |
| 3 | usage |

The keys directory for `verify` holds `*.pub` files (SPKI PEM, or the base64url of the 32 raw bytes) and `*.json` key records `{ "publicKey": ..., "not_after": "<ISO date>" }`, read recursively, and `revoked.txt` at its top. The role's own `keys/` directory is one. `verify` reports, in this order: `failed` (exit 1), then `revoked` and `expired` (exit 2) when a signature verified from a key that `revoked.txt` lists or whose `not_after` has passed, then `verified` (exit 0), then `unknown` (exit 2). A signature that names a revoked kid whose key is no longer in the directory counts as revoked. A key record that cannot be read, or a `not_after` that is not an ISO date, is an error (exit 2), so a limit is never dropped without notice. Two files for one key keep the earlier `not_after`.

A DSSE signature carries no date, so `not_after` is checked against the time of verification, which is now unless `--at` names another, such as the time a trusted log recorded the envelope. A date written next to the signature would not be signed, and the holder of the key could backdate it.

## What a signature proves

A key at rest is readable by every process of the user who owns it, so one agent can sign as another role on the same machine. An L1 signature identifies the user's machine key set for that role, not the agent process. `AGENTKEY_SIGNER=ssh-agent`, which keeps the private key in the agent instead of a file, is a later option.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
