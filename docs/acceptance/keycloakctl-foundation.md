# `keycloakctl` offline foundation

> **Historical foundation reference, not the current Issue #74 CLI contract.** The readiness/qualification examples and remote-phase descriptions below document an earlier mixed-scope design. The current Issue #74 checkpoint is local-only: `full` accepts `dev`/`ci`, runs local preparation/build/test, and seals only a local-only run-intent receipt. It does not implement readiness/qualification phases or the proposed #73 owner-approved qualification intent. See [the current offline/local migration map](issue-74-offline-migration-map.md) for this candidate's contract.

**This PR is an offline-foundation checkpoint for Issue #74, not completion of
that issue.** It adds the local setup/build/test path and a bounded read-only
preflight slice. Issue #74 must remain open. Still remaining: complete lifecycle
phase implementations and receipt parity; full target/proxy/network/App Links
preflight evidence; separately authorized live readiness and qualification runs;
and teardown/promotion safety. The live and qualification profiles are not
qualified by local tests or by the test-only fake-issuer RP fixture.

Run `./keycloakctl --help` with Python 3.11.13. For the local Java test phase, make
Java 21 and Maven available on `PATH`. The launcher finds its repository from
its own location, including when invoked outside the checkout. Explicit `--config`
paths are relative to the caller. [`scripts/lifecycle.py`](../../scripts/lifecycle.py)
remains for stages not yet migrated. `keycloakctl` provides local setup/build/test and `acceptance` owns the ordered Maven package, Surefire validation, provider-service-registration, Python-test, Python-compile, and diff-check stages used locally and by PR CI. The Surefire report validator is keycloakctl-owned. Acceptance writes a keycloakctl-owned durable receipt; this is partial phase-ownership parity.

The `acceptance --profile offline` command is the shared local/CI entry point. It performs local preflight, Maven/Surefire and canonical Python checks, provider registration, both local image builds and smokes, diff-check, and sanitized source-bound receipt writing. It retains the built local images and records cleanup as `not_run`; image retention cleanup is a separate explicit `./keycloakctl images cleanup` action. The RP fixture smoke runs the configured image entrypoint, starts a loopback listener on an ephemeral port, checks a fixed rejection response, and shuts down without issuer access. This is startup evidence, not an RP server/browser flow or qualification. The PR workflow invokes the same `./keycloakctl acceptance --profile offline` command. Resolver provenance receipts and live/remote phases remain open; this does not complete Issue #74.

## Local commands

```sh
./keycloakctl validate-config --config config/keycloakctl/readiness.json
dev_id=$(./keycloakctl setup --profile dev --config config/keycloakctl/dev.json)
# Run the currently migrated local acceptance stages through keycloakctl.
./keycloakctl acceptance --profile offline
# The canonical CI caller uses the same named profile through keycloakctl.
./keycloakctl setup --run-id "$dev_id"
# Fetches locked prerequisites on the host; `--network=none` disables build-step networking, not base-image acquisition.
./keycloakctl build --run-id "$dev_id" --config config/keycloakctl/dev.json
./keycloakctl test --run-id "$dev_id" --config config/keycloakctl/dev.json
./keycloakctl full --profile dev --new-run --config config/keycloakctl/dev.json
# Set full_id to the ID printed by full --new-run.
./keycloakctl full --profile dev --run-id "$full_id" --config config/keycloakctl/dev.json
```

Use the ID printed by the corresponding setup or `full --new-run`. `setup` with
no ID creates a new run; with an ID it only reopens that run. `full` requires
exactly one of `--new-run` or `--run-id`, and never switches profiles or picks
another run. IDs are exactly 32 lowercase hexadecimal characters. Each worktree
reserves IDs exclusively in `.keycloakctl/run-ids/`; do not delete or roll back
this ledger. It prevents reuse even if a run manifest is missing or setup is
interrupted. Non-reuse does not survive deleting or restoring the entire ledger.

The canonical manifest is stored at `target/keycloakctl/runs/<run-id>/manifest.json`,
matching the Issue #74 run-state layout. The `keycloakctl test` phase deliberately
runs Maven `package` without the `clean` goal so Maven does not erase active run
manifests and receipts under `target/`. A manually invoked `mvn clean` still removes
`target/` and destroys those records; do not run it while preserving an active
`keycloakctl` run. The separate `.keycloakctl/run-ids/` reservation ledger remains
outside `target/`, so a cleaned run ID cannot be reused, but that run cannot be
resumed without its manifest. The local `build` phase packages the Keycloak provider with Maven on the
host; Maven may resolve Java dependencies from the network. It then fetches the
commit-pinned Identity and Registry sources and hash-pinned resolver artifacts
into a temporary directory outside the repository and verifies them. It supplies
them as named build contexts. The selected local engine builds both images with
`--network=none` for build steps and verifies immutable image IDs. The run records source
and config digests for resume checks. The run-scoped images are retained locally;
no build artifacts are added to Git. Resolver input fetching and Maven dependency
resolution require host network access; the engine may also fetch a missing `FROM`
image. `--network=none` applies to build steps, not image acquisition.

The run manifest records format version, run ID, profile, config digest and
completed `setup` phase. For runs created by `setup`, the digest is over canonical
JSON; local-only `full --new-run` binds the exact supplied config bytes instead.
Resume that `full` run with byte-identical config, including whitespace and member
order, or start a new run. Reservations bind the exact manifest bytes; missing or
conflicting readback is rejected, not repaired, and never releases the ID. Verified
`build.json` and `test.json` receipts provide the local phase cursor without
rewriting the reserved manifest. Test evidence binds test inputs, build receipt,
config and provider image ID. This is a local consistency check, not protection
against someone who can rewrite run data. Keep `target/keycloakctl/runs/` and
`.keycloakctl/run-ids/` intact when preserving a run.

[The closed schema](../../config/keycloakctl/config.schema.json) and the four
examples cover `dev`, `ci`, `readiness`, and `qualification`. Without a config,
`setup` defaults to `dev` (Podman); `ci` defaults to Docker. `--profile`, if
supplied with a config, must match it. The CLI also rejects duplicate JSON keys,
floating-point spellings, non-finite numbers, non-UTF-8 input and files over 8 KiB.
Do not pass secrets in config or argv. Raw configuration values, authorization
flags, and paths are not written to the manifest or echoed in refusals.

Only remote profiles accept `remote`. Its non-secret inputs can be incomplete
at setup. The current preflight guard requires a valid configured Tailscale SSH
user and an exact expected Tailscale DNS name (`target_dns_name`), distinct
target/proxy Tailscale IPv4 addresses, one public HTTPS origin
of the form `https://<DNS-host>[:port]`
(maximum 267 characters: DNS host at most 253 characters; optional canonical
port 1–65535), with no credentials, path, query or fragment, and
`route_attested: true` for the operator's route, ACL and forwarded-header review.
The default SSH target name is `ben-x260`; `target_host` can override it. Set
`target_dns_name` to the exact expected Tailscale `Self.DNSName` (without a
trailing dot); this is checked separately from the SSH target alias. The `.invalid`
examples are intentionally non-runnable.

Read-only `preflight` is repeatable for local and live profiles. For local
`dev`/`ci` runs, it requires Python 3.11.13, Java 21, Maven, and Git, then validates
the selected local engine before issuing engine commands. Docker `DOCKER_HOST`,
Docker context selection, Podman `CONTAINER_HOST`, and Podman connection selection
are checked from their local settings; a non-local or unresolved endpoint is
rejected before any engine command. The local check validates the engine client
version, daemon/info readback, and image inventory rows with full immutable IDs;
Docker also requires Buildx, and Podman must report `Host.Security.Rootless`
exactly `true`. Probe output is
not printed, no images are built/pulled/run/removed, no Tailscale command is
invoked, and no run state is written. Success prints only `preflight passed`.

## Historical live-profile design reference (not implemented by this candidate)

The following live-profile descriptions are retained as design history only. They are not supported by the current CLI: this candidate's `full` command accepts only local `dev`/`ci` profiles, performs local preparation/build/test, and stops with a local-only run-intent receipt. Remote readiness, qualification, publish, deploy, and teardown are deferred.

For live readiness/qualification profiles preflight retains the existing local
`tailscale version` and `podman --version` checks, then uses `tailscale ssh` with the configured target user and host.
Tailscale SSH validates the destination host key against the node key advertised
by Tailscale. The preflight checks exact normalized equality with the configured
Tailscale DNS name and exact configured Tailscale IPv4 address, then requires
`podman info --format json` to
report `Host.Security.Rootless` exactly `true`. It refuses on missing tools,
Tailscale SSH refusal, identity mismatch, failed/malformed Podman readback, or
rootful Podman. This probe has no
`--allow-live` gate and does not change the run manifest; it can be repeated.
The read-only remote commands are limited to `tailscale status --json` and
`podman info --format json`; remote commands are constants, while the target
user/host are validated config fields.

This implements only the bounded local-toolchain/engine subclaim plus the
existing live target-identity/rootless-container subclaims of criterion 6;
criterion 6 remains partial. The local `dev`/`ci` check does not verify target
identity or the planned topology. The planned topology uses tailnet listeners on ports 18080 and
18081, public routes `/keycloak` and `/rp`, and Wallet App Links at
`/.well-known/assetlinks.json`; this command does not verify that topology. It
does not verify proxy Tailscale identity, fixed-port availability, actual
reviewed ACL or forwarded-header evidence beyond the operator's `route_attested`
boolean, public DNS/TLS, the App Links document, or configured origin/proxy-route
behavior. Those checks, as well as all deployment and live qualification
activity, remain out of scope for this bounded local check.

## Local build and remaining gated phases

`keycloakctl test` runs the offline Java package tests, verifies nonempty passing
Surefire reports, runs the canonical Python acceptance suite, then compiles the
lifecycle Python sources. It next checks the provider image's Keycloak 26.8.0 /
Java 21 version and runs the RP fixture image entrypoint with container networking
disabled. That smoke starts a loopback listener and checks a fixed rejection
response; it is startup evidence only, not browser or live qualification. The RP image uses the
fixture's hash-locked Python dependencies from the verified wheelhouse, then runs `diff-check`. Every stage must pass before a complete version-2 `test.json` is written. The
receipt records the ordered steps and binds completion to the test inputs, build
receipt, config, and provider image. Each failed stage stops later work and writes
a durable `failure-*.json` step receipt; a failed attempt does not create
`test.json`. Resume validates the existing source-bound success receipt rather
The PR workflow invokes `./keycloakctl acceptance --profile offline`; this invokes the same bounded local acceptance stages documented above.
Other existing lifecycle capabilities remain unmigrated, so
`scripts/lifecycle.py` stays until their replacement and caller parity are
verified.
- `readiness`: `setup → preflight → build → test → publish → deploy → configure → verify readiness → teardown`.
  The first `full` invocation runs read-only preflight and leaves the manifest at
  `setup`. Since preflight does not persist a completion marker, another `full`
  invocation repeats preflight; it does not continue to later phases in this
  slice. Build and test remain implemented only for local profiles. Intended
  readiness evidence is a non-qualifying synthetic standard Code + PKCE smoke,
  with no wallet or Registry work.
- `qualification`: same preparation through `configure`, then a manual Android
  evidence checkpoint, `integration-test` for the fixed ten cases, and
  `verify qualification` against same-run evidence. Teardown remains explicit;
  no Android management, optional signup/OID4VP cases or diagnostic evidence can
  qualify a run. The Android checkpoint and evidence ingestion are not implemented.
- Standalone phases take `--run-id`. Read-only `preflight` may be repeated with
  the same run/config at any point and never advances phase state. `teardown`
  refuses unless exact run-owned deployment resources have been independently
  read back; the foundation has no such ownership receipt, so even a completed
  `deploy` marker alone is insufficient and no teardown executes. `promote` is
  independent of readiness/qualification and #66: it requires a reviewed
  `--receipt`, explicit `--destination`, and `--allow-publish`; it remains
  unavailable until receipt and registry promotion safety are implemented.
  `publish` is a host transfer, separate from registry promotion.

`publish`, `deploy`, `configure`, live `integration-test`, `verify readiness`,
`teardown`, and `full` at a live phase require `--allow-live` on that invocation.
`promote` instead requires `--allow-publish`. Neither flag is persisted or
substitutes for separately scoped human approval. Live phases, teardown and
promotion remain unavailable through this CLI.

Exit `0` means the requested local setup, config validation, read-only preflight,
build, or test phase succeeded. Exit `2` means a refusal, such as bad input,
missing authorization or invalid phase order. Exit `3` means the next phase is
eligible but unavailable. Each `full` invocation runs only its current next step;
read-only preflight returns successfully without advancing the immutable manifest.
Standalone `build --run-id` records verified image IDs and build fingerprints;
verified phase receipts advance the local cursor. Resume rechecks source and
config fingerprints and exact image IDs before accepting existing build and test
records.

Run the public subprocess tests directly with
`python3.11 -m unittest -v scripts.test_keycloakctl`. They use scratch fixtures
and start the executable without inherited runtime credentials. The canonical
Python suite includes this module through `scripts/lifecycle.py python-tests`.
