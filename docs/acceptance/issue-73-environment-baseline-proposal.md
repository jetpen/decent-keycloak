# Proposed Issue #73 environment-baseline and run-intent contract

**Status: historical proposal document; not an owner-adopted full schema, implementation, readiness result, or qualification evidence.** PR #82 merged at `306c9415f648892615ccded06c9c496ae6dc4d20` as review-only proposal material and explicitly stated at that time that the owner had not adopted the proposal. Later comments on Issues #73 and #74 assigned baseline/projection/approval ownership to #73 and adopted the artifact split as the design basis. That later boundary-level adoption does **not** mean the proposal PR's entire schema was separately owner-ratified, nor does it authorize provisioning, execution, approval custody, or live operations. This document remains historical proposal text; the bounded #74 validator uses a narrowed baseline/projection schema at `config/keycloakctl/issue74-artifact.schema.json` and validates inputs only.

## Problem statement

Issue #73 needs a reviewed, non-secret description of one disposable environment for Keycloak #66, while Issue #74 supplies the lifecycle CLI. A single mutable “run manifest” would conflate reusable environment facts with run-specific images, operators, cases, time windows, and authorization. It would also risk treating a hash or `--allow-live` flag as proof of owner approval, and could not safely bind a completed build to the exact software later deployed.

At the time this proposal was drafted, the #73 body framed the environment as one run manifest containing run-specific fields. Later owner comments adopted the baseline/projection/run-intent split as the design basis, so this proposal is historical context rather than current issue wording. Issue #73 remains open; its live body and comments govern the outstanding environment ownership, readiness, and authorization gates.

## Proposed solution and artifact graph

Use four distinct records, linked by exact SHA-256 digests of their exact bytes:

1. **Environment baseline** — reusable, owner-reviewed, restricted, versioned JSON. It describes the approved environment and policy, pins the exact #74 runtime-config bytes, maps the fixed #66 inventory, and states profile-specific readiness. Approval of a baseline is not authorization to operate it.
2. **Case-inventory projection** — a separate immutable JSON artifact containing a deterministic projection of the ten required #66 case definitions and expected observations. The currently required IDs, in source order, are `LOGIN-01`, `TLS-01`, `TLS-02`, and `NEG-01` through `NEG-07`; the projection records that order in an explicit `case_ids` array and stores the case definitions in a map keyed by ID. The projection records the exact #66 source snapshot reference and SHA-256. The baseline stores its exact-byte hash and those ten IDs; case changes require a newly reviewed projection and baseline revision. Do not duplicate full procedures or include the optional signup/OID4VP cases.
3. **Run-intent** — immutable, restricted JSON emitted by `keycloakctl` only after local build and test complete. It binds one run to one baseline/config/case-set revision, exact software/tool/image identities, target, profile, operations/cases, and time windows. A run-intent is written before any remote mutation and is never edited in place.
4. **Owner approval and lifecycle records** — the per-run approval remains in the existing owner-controlled approval process, bound to the exact baseline, config, and run-intent hashes, target, operations/cases, and windows. A separate append-only owner-controlled lifecycle record tracks active, superseded, revoked, or expired state by exact artifact hash. These records are manually verified by the operator; their hashes establish byte identity, not owner identity, approval, or truth.

All machine-readable records use strict, versioned JSON with closed field sets. The original [PR #82 proposal schema](issue-73-artifact-schema-proposal.json) remains historical proposal material; its whole schema was not separately owner-ratified by the later #73/#74 design-boundary adoption. The narrower [#74 offline artifact schema](../../config/keycloakctl/issue74-artifact.schema.json) is this candidate's strict local input schema for the baseline/projection split. The split is the adopted design basis; review of the concrete field set remains pending, and the schema does not define run-intent or lifecycle records. Validation uses Draft 2020-12 and rejects duplicate JSON members before schema checks. Exact-byte SHA-256 cross-bindings are checked separately. These local checks neither authenticate an owner review reference nor establish approval, readiness, authorization, or truth.

## Environment baseline

Each baseline revision has a stable `baseline_id`, monotonically increasing `revision`, exact-byte digest, and `supersedes` reference when applicable. Approved revisions are append-only. Only an active revision may start a new run. Superseded revisions remain available for historical run binding; an existing run cannot resume deployment under changed baseline/config values and may only perform exact, separately authorized cleanup against its original intent and target. A revoked baseline blocks new and continuing mutations; cleanup requires a fresh cleanup-only approval bound to the original run-intent and target.

The baseline should contain or reference, without secret values:

- The exact SHA-256 of the #74 runtime configuration and its non-sensitive artifact reference.
- The stable Tailscale machine/node identity, expected OS account, locator DNS/IP values, caller-principal scope, and owner-attested SSH ACL. Locators are not identity.
- The external proxy/route identity and configuration hash, public HTTPS/App Link origin, fixed listener/route bindings, TLS policy, and references to owner-reviewed route, ACL, and forwarded-header attestations. The proxy is operator-managed and is not independently observed from the target host; public probes and operator attestations remain distinct evidence.
- The supported Keycloak/RP source and runtime constraints, realm/provider and OIDC-client configuration, browser version, and approved Wallet artifact/package/signer and Android target when available. Actual per-run image digests and exact executed source/tool identities belong in run-intent.
- A reference and exact-byte hash for the separate #66 projection, plus the required ten case IDs. The readiness and qualification profiles have separate plans; readiness is non-qualifying and cannot satisfy any #66 case or receipt.
- Secret roles and custody owners only. Secret values, credential locators, tokens, wallet material, raw callbacks, and transaction URLs stay out of the baseline and run records.
- Fresh-disposable-identity and clean-browser/session policy; deterministic resource ownership and teardown/readback policy; profile-specific readiness states; retention period; and the required host-clock synchronization policy and owner-declared maximum drift.

A baseline may be owner-reviewed while prerequisites are pending, but each profile must explicitly identify its readiness state. The CLI may use only a profile whose required gates are `ready`; missing, pending, blocked, or unknown prerequisites fail closed. Baseline approval never implies per-run authorization.

Any change to target/access policy, proxy route/ACL/header policy, runtime config, or another approved environment value requires a new baseline revision. Every per-run approval re-attests that the target, access policy, and proxy route/ACL/header contract still match the pinned baseline. Drift blocks the run until the owner reviews a new baseline.

## Run-intent and approval

After build/test, the CLI seals one immutable run-intent with at least:

- Unique run ID, selected readiness or qualification profile, baseline ID/revision/hash, exact runtime-config hash, case-projection hash, and local build/test receipt hashes.
- Repository/source commit and worktree state; a restricted immutable source-input bundle hash covering exact build/test inputs, including tracked modifications and untracked inputs; separate image-source and `keycloakctl` build/test-source digests; observer helper version/hash; and both actual Keycloak and RP image identities as immutable repository digests or content-addressed image IDs.
- Pinned target machine/node identity and OS account, route/listener bindings, exact planned lifecycle operations, exact selected case IDs, assigned operators/evidence owners, and opaque run-scoped disposable identity/session/resource handles.
- A normal UTC execution window and a separate cleanup grace window. The normal window permits only its approved operations. After it expires, no new deploy/configure/case operation may start. A mandatory read-only reconciliation for a mutation started within the valid window may finish after expiry. Exact-ID teardown and fresh absence readback are permitted only in the explicitly approved cleanup grace window.

The owner-controlled approval record must cite the exact baseline/config/run-intent hashes, target, operations/cases, normal window, cleanup grace, and refreshed route/access attestations. It authorizes only that scope. The operator manually verifies that the record is current and active at each CLI invocation. `--allow-live` is separately required on every live invocation and is not proof of approval. If revocation is known during a multi-step invocation, finish only the already-started mutation's mandatory readback, then block subsequent mutations.

The source-input bundle is an immutable capture of precisely the inputs consumed by the build. Its definition must bind relative paths, exact bytes, file modes, symlink targets, and the explicit exclusion list for generated/non-input files. It must include tracked modifications and untracked build inputs when the worktree is dirty. The base commit and clean/dirty state remain useful provenance, but neither replaces this bundle. Run-intent generation must fail closed if it cannot produce and verify the complete bundle.

`full` may perform local preparation and explicitly read-only preflight probes. When build and test succeed, it emits the immutable run-intent and stops before `publish` or any other remote mutation. The operator obtains owner approval out of band; a separate resume invocation supplies the approval reference/hash and `--allow-live`. A changed source, CLI/helper, image, config, target, operation/case scope, or window requires a new intent and approval.

## Time and target-observer boundary

Before each remote mutation, the CLI checks the approved UTC interval against the operator host's UTC clock. The OS must report clock synchronization and the measured/declared drift must satisfy the baseline's owner-set maximum; unavailable sync state or missing/out-of-policy tolerance fails closed. Do not assume a local wall clock is trustworthy or use an unapproved external time service.

Authenticated target readback is direct, read-only Tailscale SSH to the pinned machine identity and expected OS account. Check target identity with `tailscale whois --json` before and after each observer session; verify the current caller is within the baseline's principal scope. Use a repo-pinned, versioned observer helper streamed over the authenticated session. Accept only strict allowlisted JSON bound to the nonce, helper hash/version, baseline hash, run-intent hash, and target identity. Discard raw stdout/stderr; retain only the parsed allowlisted observation as restricted run evidence.

Every mutation completion requires a fresh readback in the same invocation before the local phase cursor advances. On absent, malformed, stale, or mismatched readback, preserve partial resources, record failure, leave the run incomplete, and do not auto-retry or roll back. Later recovery begins with fresh read-only reconciliation. Teardown requires fresh pre-delete observation matching the immutable intent and recorded exact resource IDs, deletes only those IDs, and requires fresh post-delete observation proving absence. Any conflict or ambiguous ownership stops.

## Privacy, access, and retention

Keep exact baseline/config/case-projection artifacts in an access-restricted, versioned owner-controlled store. Grant access only to the provisioning owner, assigned operators, and designated reviewers. Keep run-intents and parsed observer records in restricted per-run storage; do not expose them to public issues or PR CI. Public issues and receipts contain only sanitized summaries and non-sensitive references/hashes. A hash is not confidentiality protection and must not be published if it would reveal sensitive low-entropy values.

The baseline records an owner-approved retention period. Restricted run-intents and parsed readbacks survive teardown until that period expires; deletion is a separate owner-controlled action. Retain sanitized public receipts/summaries separately. Never persist credentials, private keys, proofs, tokens, raw callbacks, transaction URLs, or unredacted personal data.

## Review questions and verification outline

PR #82 historically contained documentation and a proposed JSON Schema only. Its proposal-only status at merge is preserved above. The later issue comments adopted the baseline/projection/approval ownership split as a design boundary, but did not separately ratify the proposal's full schema. This implementation adds only offline validation of baseline and projection inputs; it does not implement artifact persistence, run-intent/source capture, approval verification, lifecycle phases, or environment qualification.

- Owner approval/custody integration and authenticated active/revocation checks.
- Clock-sync/drift policy enforcement at every authorized operation boundary.
- Observer/deployment/teardown flows with exact resource ownership and readback.
- Qualified case-evidence ingestion and canonical receipt generation.
- Cross-check of schema and semantic validators against the final owner-adopted contract.

These items were unresolved and untested in PR #82; some remain out of scope for this bounded validation slice. The proposal PR's own verification was limited to JSON syntax and repository whitespace checks. The current CLI tests validate only the public offline input-checking behavior described in Issue #74's migration map.

The later #73/#74 issue comments adopt the split as the design basis and assign artifact ownership; they do not ratify each field of the PR #82 schema or approve concrete environment values, readiness, authorization, or a live operation. Before any live use, the owner-controlled process must supply and accept the actual restricted baseline/projection/config bytes, access and route attestations, profile prerequisites, clock policy, retention, teardown policy, and approval custody. Issues #73, #74, and #66 remain open unless closed through their separate acceptance criteria.
