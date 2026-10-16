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

## What a signature proves

A key at rest is readable by every process of the user who owns it, so one agent can sign as another role on the same machine. An L1 signature identifies the user's machine key set for that role, not the agent process. `AGENTKEY_SIGNER=ssh-agent`, which keeps the private key in the agent instead of a file, is a later option.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
