# Security Policy

## Reporting

Report a vulnerability through GitHub's private vulnerability reporting on this repository (Security tab, Report a vulnerability). Do not put key material, exploit details or a working forgery in a public issue.

## What agentkey protects, and what it does not

- A role key is the user's key for that role on that machine, not necessarily a unique agent process: every process of that user can read it. A signature shows which role's key set signed, not which process.
- Key files are created with mode 0600, never replaced, and refused by `load` when their mode is wider or they are a symbolic link. On Windows the user's access control on `%APPDATA%` protects them instead.
- Verification is offline, against a directory of trusted public keys. A signature from a trusted key that does not verify fails the whole result; it is never skipped. Revocation (`revoked.txt`) and expiry (`not_after`) are checked at verification time, so a revoked or retired key stops verifying without touching what it signed.
- The binding to a person uses OpenSSH's own signature format through `ssh-keygen -Y`. agentkey does not reimplement it.
- agentkey makes no network calls. Its only runtime dependency is `node:crypto`.

## Reporting a compromised key

Run `agentkey revoke <role>` on the machine that holds the key and add the revoked kid, with its date, to the `revoked.txt` of every directory of trusted keys that lists it. Then `agentkey init <role>` makes a new key, and its public key is shared again.
