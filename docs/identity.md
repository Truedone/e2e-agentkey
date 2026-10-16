# What an agentkey identity is, and how to isolate it

A role key identifies the user's key for that role on that machine, not a unique agent process. The key file is `<home>/keys/<role>.key`, mode 0600, so every process running as that user can read it: two agents of the same user can sign as each other's roles, and a signature says which role's key set signed, never which process. The binding (`agentkey bind`) adds the person whose SSH key vouches for that key set. Nothing below changes what a signature means; each option narrows who can make one.

| Option | What it gives | What it costs |
|---|---|---|
| The key file (`AGENTKEY_SIGNER=file`, the default) | Any process of the user signs, with no prompt. | Nothing to set up; no isolation between that user's processes. |
| ssh-agent with per-use confirmation (`AGENTKEY_SIGNER=ssh-agent`, the key added with `agentkey agent-add <role>`, which sets the same confirm constraint as `ssh-add -c`) | The private key is held by the agent, and with `--remove` it no longer sits readable on disk. Each signature waits for a person to confirm it in the agent's prompt (ssh-askpass), so an agent process cannot sign unseen. | A person at the machine for every signature; the key is gone when the agent stops unless it is added again from a backup. |
| A hardware key through ssh-agent (an `ed25519-sk` key on a FIDO token) | The private key never leaves the token, and each signature needs the token to be touched. These signatures are OpenSSH signatures, verified with `ssh-keygen -Y verify`, and recorded as `signer: sk`. | A token per person; the signature is not a plain Ed25519 DSSE signature, so a DSSE verifier alone does not check it. |
| Running as one OS user per agent, each with its own `AGENTKEY_HOME` | The operating system keeps one agent from reading another's key file: a role key then does identify one agent's account. | An account per agent, and the agent runs under it. |

Every signature records how it was made: `signer: file`, `signer: ssh-agent`, `signer: keyless` (Sigstore, `signKeyless`) or `signer: sk`.

## Rotation

`agentkey rotate <role>` makes a new key for the role and signs a rotation statement with the old one: the old kid, the new kid, the new public key and the date. The statement is a DSSE envelope in `rotations/`, and the old key's record gets `not_after` set to that date. A receiver whose trust directory holds the old public key and the rotation statement accepts signatures by the new key, because the old key, trusted and not revoked at that date, vouched for it; signatures by the old key made after the date are expired. Revocation (`revoked.txt`) and expiry (`not_after`) are checked as for any key.
