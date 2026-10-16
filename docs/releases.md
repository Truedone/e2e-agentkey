# Releases

Each published version, the commit its tarball was built from, and what the registry serves for it.

## @optitransfer/agentkey@0.1.0

| | |
| --- | --- |
| Published | 2026-10-16T22:22:33.127Z, by the `optitransfer` npm account, tag `latest` |
| Commit | 625d6d9cd199faec44c5729e3d531cf943842b57 |
| Tarball | `optitransfer-agentkey-0.1.0.tgz`, https://registry.npmjs.org/@optitransfer/agentkey/-/agentkey-0.1.0.tgz |
| shasum | 518f9e5620cc061a4c0f92f298517f8e9396dbd4 |
| integrity | sha512-SBE/3Ec2ueOrls0L6BRPIrxrzvDs/OlLwjcszPjruG6tY1dDykLhA5q6sDoza1+qizPFfVDN+b9IkAyLa46sZg== |

`npm pack` in a clean checkout of that commit gave the shasum and integrity above before the publish, and the registry serves the same two values for 0.1.0.

The publish was made by hand with the owner's two-factor approval, not by the release workflow, so 0.1.0 carries no provenance attestation: npm builds one only for a publish from a CI identity. A later release through the release workflow with a CI credential is where provenance is measured.

Check a download against this record:

```sh
npm view @optitransfer/agentkey@0.1.0 dist.integrity
```
