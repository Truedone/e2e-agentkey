# Contributing

## How work lands

The work is split into tasks in `proofline.json`, each with its scope and its acceptance criteria. A change states the task it belongs to in its commit subject, stays inside that task's scope, and comes with the tests that show it: a test that fails on the parent commit and passes on the change. `npm test` runs the suite, on Node 22 or later, with no runtime dependencies.

## What a change keeps true

- No runtime dependency: the core uses `node:crypto` only.
- A key file is never replaced and never readable by anyone but its owner (mode 0600).
- Verification never skips a signature it cannot check: a failed signature from a trusted key fails the whole result.
- Exit codes keep their meaning: 0 ok, 1 verification failed, 2 an unknown, revoked or expired key or missing input, 3 usage.

## Sign-off

Each commit needs a Developer Certificate of Origin sign-off (https://developercertificate.org/). Put this line in the commit message, with the name and email of the commit:

Signed-off-by: Name <email>

`git commit -s` adds it. There is no contributor licence agreement.
