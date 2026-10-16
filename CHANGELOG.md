# Changelog

## Unreleased

- `signDSSE`, `verifyDSSE`, `pae` and `statement`: DSSE envelopes with one Ed25519 signature per envelope, verification that lists each signature as verified, unknown or failed and fails the whole result on a failed known key, and in-toto Statement v1. Tested against DSSE's protocol test vector and against the sigstore verifier. (AK-02)
- `generate(role)`, `load(role)` and `kid(publicKey)`: one Ed25519 key per agent role, stored as PKCS8 PEM with mode 0600 under `$XDG_CONFIG_HOME/agentkey/keys` (`%APPDATA%/agentkey` on Windows, `AGENTKEY_HOME` overrides). A key file whose mode is not 0600 is refused with `AGENTKEY_INSECURE`. The key id is hivevault's replica key id scheme. (AK-01)
