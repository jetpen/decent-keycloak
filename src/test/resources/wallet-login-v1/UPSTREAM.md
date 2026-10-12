# Upstream vector source

These fixtures are byte-for-byte vendored from `jetpen/decent-ecosystem`, branch `feat/wallet-login-v1-vectors`, based on protocol package revision `5fa46362dea1c7b1f53a27df3f5fc0a60556d1ef`.

Upstream source paths:

- `docs/protocol/wallet-login/v1/manifest.json`
- `docs/protocol/wallet-login/v1/vectors/valid-basic.json`
- `docs/protocol/wallet-login/v1/vectors/negative.json`

The GitHub branch has not yet been pushed, so a remote commit SHA for the new vector files is not available. Once ecosystem PR #46 is reviewed/merged, update these vendored bytes and this provenance file to the exact merged commit. The tests verify the local fixture hashes against the copied upstream manifest.
