# YouthScout signer

This public repository hosts a narrowly scoped GitHub Actions signer for private YouthScout release gates.

It contains **no private YouthScout source, Telegram routing metadata, plaintext gate requests, or private keys**. Pending gate requests are authenticated encrypted envelopes; the job decrypts them only after Environment approval and uploads only signature files.

## Mandatory GitHub setup

Create Environment `youthscout-signing` and add these **Environment secrets**:

- `AUDIT_SIGNING_KEY`
- `AUDIT_SIGNING_KEY_PASSPHRASE`
- `DEMO_SIGNING_KEY`
- `DEMO_SIGNING_KEY_PASSPHRASE`

Before triggering `Sign approved YouthScout gates`:

- run it only from protected `main`;
- set deployment branches to `main` only;
- restrict workflow dispatch to the repository owner;
- do not enable admin bypass;
- review every PR changing workflows, public keys, encrypted requests, or validation code.

The job verifies that each secret key corresponds to its committed public key, validates exactly two decrypted request files, signs only those files, and uploads only their detached signatures for seven days.
