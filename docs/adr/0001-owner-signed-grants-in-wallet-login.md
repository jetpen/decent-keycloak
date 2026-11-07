# ADR 0001: Owner-signed site grants in wallet login

- **Status:** Proposed overall; the **Storage: resource authorization** subsection is accepted for Storage interoperability only. Broader owner-signed grant-envelope and WordPress decisions remain proposed; implementation is not authorized.
- **Date:** 2026-11-03
- **Scope:** Architecture for issue [#56](https://github.com/jetpen/decent-keycloak/issues/56)
- **Implementation:** Not authorized by this proposal

## Context

Keycloak issue #56 follows this broader owner-signed site-grant direction, but the Storage subsection records a narrow exception: Storage accepts only its native role-only resource-authorization profile as its interoperability contract. The exception does not adopt the owner-signed envelope or WordPress decisions. It creates no runtime, build, or deployment dependency on `decent-simple-storage`: Keycloak makes no Storage call during login or token issuance and does not import or package Storage implementation artifacts. The Storage role-only profile was first recorded in `decent-simple-storage` PR [#20](https://github.com/jetpen/decent-simple-storage/pull/20) at commit [5fb4cd41ad33418a77268ef198f6e0d973f85053](https://github.com/jetpen/decent-simple-storage/commit/5fb4cd41ad33418a77268ef198f6e0d973f85053); its wallet-only Master Account Entity boundary was clarified by PR [#21](https://github.com/jetpen/decent-simple-storage/pull/21) at commit [697fbd6852ad7926a142775878752d56c0ea9bf8](https://github.com/jetpen/decent-simple-storage/commit/697fbd6852ad7926a142775878752d56c0ea9bf8). The current canonical file is `docs/specs/python-storage-resource-server-mvp.md`, SHA-256 `f39bf76e53724acdefb67422f58eb3d9d16c8883a7657105d914f3279a2a427c`. Independent security and cross-repository reviews of the PR #20 role-only profile were bound to substantive draft SHA-256 `754475a0abe106edf8a721d71d68b812be629bd52d05120ec93746fa22af7851`; later changes to that candidate were limited to review/status metadata and final blank-line cleanup, not contract text. Those reviews found no remaining material blocker in that profile; they are not a review record for the separate PR #21 Master Account Entity boundary clarification. Native Keycloak role-token output has since been boundedly qualified for Keycloak 26.8.0 and the recorded configuration through issue #61 / PR #62; no Storage implementation or production readiness is implied.

This proposal does **not** change either existing profile:

- `decent-wallet-login-v1` remains the identity-and-challenge proof. Its exact proof members and signed bytes are unchanged; it is not extended with Storage fields.
- Storage semantic-v1 remains unchanged and Storage-specific. Its existing grant bytes and semantics are not repurposed as a universal site-grant envelope.

This ADR is about the Proposed owner-signed resource-grant envelope. The separate, versioned OID4VP Account Entity disclosure profile in ecosystem [#51](https://github.com/jetpen/decent-ecosystem/issues/51) is for relying-party signup: only after the RP validates successful OIDC for the same transaction, the wallet directly discloses selected, self-asserted fields to the RP through a transaction-bound, noninteractive continuation. It is not a Storage grant and does not change Storage semantic-v1. The Master Account Entity is wallet-owned and persisted only in the existing authenticated wallet-container v2 payload; Storage and other site components never accept, store, return, discover, mirror, or replicate it, including as ciphertext. The disclosed profile fields do not go to Keycloak or Storage. Ecosystem #51 owns the wire/schema/continuation details and remains open; this ADR does not authorize that profile's implementation.

The repository currently implements the wallet-login authenticator, not this general grant envelope or any grant-derived token-claim issuance path. This document records the Keycloak owner's selected direction for cross-project review; it is not yet a shared protocol specification or implementation handoff. Storage prompt-revocation/live RFC 7662 status is unsupported and must not be advertised; a Storage consumer must reject that profile for this issuer.

## Proposed direction

Use the existing interactive OIDC authorization-code flow and wallet-login integration. Do not add the Storage-specific private JWT Authorization Grant provider from Storage #17, a new custom OAuth grant type/token endpoint, or a custom OIDC claim-mapper SPI. The existing wallet-login extension is the proposed place to verify wallet artifacts; standard OIDC authorization-code issuance and PKCE remain the token flow.

Keycloak client roles are the native authorization claims for later requests: roles are assigned to mapped users/groups by realm operators or an existing identity-governance process, not created or changed by the wallet provider. Use distinct client roles per application/resource, emitted in the corresponding access token under `resource_access.<client_id>.roles`. Any valid Keycloak SSO session with the assigned role may receive those role claims, regardless of how that session was established; the role-only path does not require wallet reauthentication. Normal Keycloak token and refresh lifetimes apply to role-only claims.

Grant-derived claims are not currently supported. This includes Storage `storage_authorization` and `storage_identity`; they must not be issued until a native-safe lifecycle that guarantees initial-token-only emission and prevents re-emission on refresh or later SSO issuance is demonstrated and approved by the relevant contract owners. Keycloak 26.8's [`AuthenticationSessionModel`](https://github.com/keycloak/keycloak/blob/26.8.0/server-spi/src/main/java/org/keycloak/sessions/AuthenticationSessionModel.java) describes user-session notes as being applied when a client session attaches; [`TokenManager.attachAuthenticationSession`](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/protocol/oidc/TokenManager.java#L510-L557) copies them into the persistent user session, and [`UserSessionNoteMapper`](https://github.com/keycloak/keycloak/blob/26.8.0/services/src/main/java/org/keycloak/protocol/oidc/mappers/UserSessionNoteMapper.java#L84-L100) reads but does not consume them. This proposal does not authorize a custom claim-mapper SPI or other token-issuance extension as a workaround.

A new, provider-neutral **owner-signed site grant** accompanies (but does not modify) the existing login proof. The common envelope binds one grant to:

- the owner identity;
- the exact requesting site/OIDC client;
- exactly one target audience;
- one use and an expiry;
- a profile identifier and that profile's owner-authorized payload; and
- the same pending wallet-login transaction/challenge as the login proof.

The precise wire field names, encoding, signature profile, and transaction-binding mechanism remain to be specified by the contract owners. For this proposed resource-grant flow, the site's grant request travels in the OIDC authorization request and Keycloak relays it to the wallet through the existing wallet-login transport; there is no direct site-to-wallet grant-request channel. This statement does not cover the separate OID4VP account-disclosure profile in ecosystem #51. Keycloak supports only standard `scope`, the single `resource` value, and standard OIDC `claims` for this design. It does not use Preview parameterized scopes, custom request parameters, or an RFC 9396 RAR processor. These parameters select only statically configured, allowlisted client scopes and claim paths; the request itself is not authority. A grant is never a multi-audience credential. For Storage, the requesting OAuth client and the Storage resource audience are distinct values. For WordPress login, the site/client is the OIDC audience.

Site profiles may define their own payloads and scope semantics without a shared inner schema. A wallet must recognize a trusted, versioned renderer/profile before asking the owner to sign; an unknown profile is rejected. The grant's profile payload is not authority merely because a site requested it: the owner-signed artifact must cover the exact approved request, and the addressed service must reject profiles it does not support.

## Authorization-code flow

```mermaid
sequenceDiagram
    autonumber
    participant RP as Relying party
    participant B as Browser
    participant KC as Keycloak
    participant W as Wallet
    participant Reg as Registry
    participant RS as Storage resource server

    RP->>B: Redirect to Keycloak with OIDC authorization request
    B->>KC: client, redirect, state, nonce, PKCE, static scope/resource/claims
    KC->>KC: Enforce client, resource, client-scope, and claim-path allowlists
    alt Valid Keycloak SSO and assigned client role; role-only request
        KC->>KC: No wallet reauthentication; apply native client-role scope mapping
        KC-->>B: Authorization code
        B-->>RP: Authorization response with code and state
        RP->>KC: Exchange code with PKCE
        KC-->>RP: Access token has resource_access.<client>.roles
        alt WordPress login
            RP->>RP: Map OIDC identity by (iss, sub) from ID token
        else Storage access
            RP->>RS: Present access token (single aud = Storage resource)
            RS->>RS: Validate issuer, lifetime, audience, and client-role claims
            Note over RS: No Registry lookup per Storage request
            RS-->>RP: Authorize or deny
        end
    else Request requires an initial owner-grant-derived claim
        KC-->>B: Start wallet transaction; relay bound OIDC request
        W->>KC: Retrieve request/challenge over wallet-login transport
        Note over W: Trusted renderer displays request; owner approves permitted subset
        W->>KC: Submit unchanged login-v1 proof plus separate signed grant
        KC->>Reg: Resolve current owner identity/key
        Reg-->>KC: Current identity/key or unavailable
        KC->>KC: Verify proof, grant, bindings, expiry, and one-use status
        alt Registry unavailable or proof/grant invalid, expired, mismatched, or replayed
            KC-->>B: Authorization error; no code issued
        else Valid proof and grant
            KC->>KC: Grant-derived claim still blocked: native note is persistent
            KC-->>B: No token issued satisfying the grant-claim request
        end
    end
```

This diagram covers only the proposed owner-signed resource-grant flow. For that flow, the website-to-Keycloak OIDC authorization request is the channel for the grant request, relayed by Keycloak through the wallet-login transport. It does not depict the separate OID4VP account-disclosure continuation in ecosystem #51, which is direct wallet-to-RP after successful OIDC. Role-only claims use native Keycloak client roles and do not require wallet reauthentication for a valid SSO session. The diagram marks owner-grant-derived claim issuance as blocked: the native session-note mapper does not provide the required initial-token-only lifecycle.

1. **The relying party starts OIDC.** The website sends the browser to Keycloak's authorization endpoint using its registered client and redirect URI, `state`, `nonce`, and PKCE parameters. It may request only statically configured `scope`, the single `resource` value, and standard OIDC `claims`. No Preview parameterized scopes, custom request parameters, or RAR are used. Requested claims, scopes, profile, or audience are requests—not owner authorization.
2. **Keycloak binds and relays the request.** Keycloak validates the OIDC client, redirect URI, one target resource, requested static client scopes/claim paths, and realm policy. Client, resource, scope, and claim-path combinations must be explicitly allowlisted. The standard `resource` value does not itself authorize a resource. For the wallet flow, Keycloak binds the exact client, audience, request, authentication session, and fresh challenge, then relays the request through the existing wallet-login transport.
3. **The wallet presents consent.** When the wallet flow is used, the wallet obtains request details from Keycloak's wallet-login transport—never from a direct site-to-wallet channel—and displays the relying site, target audience, profile/version, requested action/scopes, and relevant claim disclosure in a trusted renderer. The owner can approve only the displayed request (or an explicitly represented subset).
4. **The wallet returns two artifacts.** It submits the unchanged `decent-wallet-login-v1` proof and a separate owner-signed site grant. Both identify the same owner and are bound to the same challenge/transaction. The grant also binds the exact requesting client, its single target audience, approved profile payload, one-use identifier, and expiry. A mismatch, changed request, or replay fails closed.
5. **Keycloak verifies before issuing.** For the wallet flow, the integration verifies the login proof and grant signature against the owner's current Registry identity/key, validates client/audience and challenge bindings, checks expiry, and atomically enforces one-use replay protection. A Registry outage is an issuance failure, not an identity miss or a reason to issue a weaker wallet-authenticated result. Separately, role-only requests may use any valid Keycloak SSO session: the native client-role mapper emits only assigned, scope-permitted roles. Role assignments are not created or changed by the wallet provider.
6. **Keycloak returns an authorization code.** When the requested result is issuable, Keycloak resumes standard OIDC authorization-code flow and redirects to the registered RP URI with code and original `state`; tokens are not returned as the browser callback. Requests requiring owner-grant-derived claims remain blocked until a native-safe initial-token-only mapping lifecycle is demonstrated.
7. **The relying party exchanges the code.** The RP exchanges the code with PKCE. WordPress login maps `(iss, sub)` from the ID token; `decent_identity_id` may be disclosed in the ID token only for explicit signup, but that initial-only grant-derived claim is currently blocked. Storage receives an access token with one Storage audience and client-role claims under its `resource_access` entry; no `storage_authorization` claim is defined by this ADR.

The precise boundary for profile-specific semantic validation is still open: the common issuer must validate the owner signature and envelope bindings before signing claims, but the owners must decide whether Keycloak also validates each profile's semantics or forwards a verified, typed profile for the addressed resource server to interpret. No implementation may treat an opaque or unsupported profile as authorization.

## Site profiles in scope for this proposal

### WordPress: login and signup

Each WordPress grant authorizes one explicit action for one exact site/client:

- **`login`:** issue the ordinary OIDC result. The relying party maps the stable `(iss, sub)` pair and does not query the Registry for a returning login.
- **`signup`:** the intended initial token set may additionally disclose the exact `decent_identity_id` in the ID token. The relying party must resolve that exact identity against the current Registry before creating the local account. This claim is not currently issuable under the native-only constraint because the available session-note mapping does not guarantee one-time emission.

Keycloak client roles for the WordPress client, if configured, are separate role claims in its access token; they do not replace the ID-token `(iss, sub)` identity mapping. Role names and WordPress behavior remain application-owned.

Neither action grants general profile-data disclosure or Storage access. Login and signup are generic action names, but a signed grant for one site cannot be reused at another site.

### Storage: resource authorization

For the accepted Storage-only interoperability profile, the Storage client receives operator-assigned native roles under `resource_access.<storage-client-id>.roles` in ordinary signed access tokens. The exact closed Storage role vocabulary and mapping are Storage-owned: `storage:read`, `storage:create`, `storage:update`, `storage:delete`, `storage:enrollment:read`, and `storage:enrollment:withdraw`. Storage validates the configured issuer/signature/JWKS, exact single Storage audience, token lifetime and exact `(iss,sub)` mapping. An audited, operator-reviewed one-to-one mapping per issuer resolves that exact subject to the raw Registry owner; approval records the mapping only after the operator verifies the Keycloak subject against the enrollment proof's exact Registry identity. Roles authorize their named actions across all objects of that mapped owner; Storage retains local enrollment, quota, object and lifecycle checks. This profile deliberately has no per-object digest, purpose, client/site, consent or JSON Pointer scope: reads return the complete current object and updates are full replacements guarded by `If-Match`. Enrollment submission remains a separate owner-signed proof validated by Storage against current Registry identity/key/sequence; status and withdrawal use the ordinary role-bearing access token and mapped subject, with no `storage_identity` token or per-request Registry lookup. Normal Keycloak expiry and refresh apply. Storage imposes no additional maximum token lifetime or maximum revocation-delay guarantee; a previously issued token remains valid for its roles until `exp`, subject to Storage's local checks. Since the active subject-owner mapping is created at approval, pending, rejected, and never-approved subjects cannot query enrollment status and receive only the proof-submission receipt.

This narrow profile is accepted for Storage interoperability only. It does not adopt the owner-signed grant envelope, change WordPress behavior, qualify Storage-side validation, owner mapping, route authorization, other Keycloak releases, or production readiness, authorize grant implementation, or change the broader Proposed status of this ADR. The canonical Storage contract is `decent-simple-storage/docs/specs/python-storage-resource-server-mvp.md`: its role-only profile was first recorded in PR [#20](https://github.com/jetpen/decent-simple-storage/pull/20) at commit [5fb4cd41ad33418a77268ef198f6e0d973f85053](https://github.com/jetpen/decent-simple-storage/commit/5fb4cd41ad33418a77268ef198f6e0d973f85053), and its wallet-only Master Account Entity boundary was clarified in PR [#21](https://github.com/jetpen/decent-simple-storage/pull/21) at commit [697fbd6852ad7926a142775878752d56c0ea9bf8](https://github.com/jetpen/decent-simple-storage/commit/697fbd6852ad7926a142775878752d56c0ea9bf8). The current `main` file SHA-256 is `f39bf76e53724acdefb67422f58eb3d9d16c8883a7657105d914f3279a2a427c`. The PR #20 role-only profile was independently reviewed at substantive draft SHA-256 `754475a0abe106edf8a721d71d68b812be629bd52d05120ec93746fa22af7851`; later changes to that candidate were limited to review/status metadata and final blank-line cleanup, not contract text. Those reviews are not a review record for the separate PR #21 Master Account Entity boundary clarification. Storage issue #18 remains open for its human disposition.

The owner-grant-derived Storage claim path is unsupported by this proposal. It does not issue `storage_authorization` or `storage_identity`, and neither may be inferred from a role or object-access grant. Storage prompt-revocation and live RFC 7662 grant status are also unsupported: this Keycloak design must not advertise them, and Storage must reject that profile for this issuer. Any future grant-derived claim or live-status capability requires a separately approved design and demonstrated safe token lifecycle.

## Security invariants

- The client request is untrusted input until the owner signs a grant that covers the exact approved profile/action, audience, and payload.
- When a wallet grant is used, its login proof and grant must match on owner, client, challenge/transaction, and request; cross-transaction substitution is rejected.
- Each grant has one exact requesting client, one target audience, one-use identity, and an expiry. Reuse, audience widening, or client substitution is rejected.
- For wallet-proof/grant issuance, Keycloak fails closed when current Registry verification, signature validation, transaction binding, or replay protection is unavailable.
- Storage validates the issuer-signed token and required claims on each protected request; this proposal does not require a Storage-to-Registry call on each request.
- Unknown wallet renderers/profiles and unsupported resource-server profiles are rejected rather than interpreted as generic consent.
- The existing wallet-login-v1 proof and Storage semantic-v1 bytes remain unchanged.
- Keycloak role authorization uses assigned per-client roles and explicit client role-scope mappings; only the corresponding access token carries those roles under `resource_access.<client_id>.roles`.
- Role claims may be issued to any valid Keycloak SSO session with the matching role, regardless of the session's authentication method. The wallet provider never assigns authorization roles.
- Owner-grant-derived claims are initial-token-only and expiry-bounded, but must not be emitted until a native-safe mechanism prevents session-note re-emission on refresh and later SSO issuance. No custom claim-mapper SPI is authorized.

## Decisions still required before implementation

1. Ecosystem owners must specify the new common envelope, canonical bytes/signature, profile identifier/version rules, exact transaction binding, expiry, and one-use storage semantics.
2. OIDC owners must define exact mappings from the approved standard `scope`, single `resource`, and standard `claims` values to configured profiles and client scopes. Custom request parameters, Preview parameterized scopes, and RAR are excluded. The request travels in OIDC and Keycloak relays it to the wallet.
3. Wallet owners must define distribution, trust, versioning, and display requirements for profile renderers.
4. Bounded native client-role token qualification is complete for Keycloak 26.8.0 and the pinned image/configuration in [issue #61](https://github.com/jetpen/decent-keycloak/issues/61) / [PR #62](https://github.com/jetpen/decent-keycloak/pull/62): 17/17 cases passed, including role-scope intersection, exact single Storage audience, wrong/widened audience, other-client/realm-role rejection, and refresh behavior. This does not qualify another release, Storage-side validation, owner mapping, route authorization, or production readiness. Separately, initial-only grant-derived claims remain blocked until a native-safe lifecycle is demonstrated by tests covering initial code exchange, refresh, and later SSO authorization. The current `UserSessionNoteMapper` alone fails this requirement because it reads persistent notes without consuming them.
5. Storage has accepted the native role-only profile for Storage interoperability only: the six roles, their owner-wide operation semantics, and the audited exact `(iss,sub)`→Registry-owner mapping are recorded in the Storage-owned contract cited in the Storage subsection. Keycloak role-claim output is boundedly qualified as described in decision 4; this ADR does not authorize grant implementation. The old dynamic owner-grant authorization profile is unsupported for this issuer. Any future grant-derived `storage_authorization`/`storage_identity` or prompt-revocation profile requires a separate Storage contract decision and qualification; these are not requirements of the accepted role profile.
6. Cross-project status must preserve ownership boundaries: ecosystem wallet-login issue [#46](https://github.com/jetpen/decent-ecosystem/issues/46) has an approved `decent-wallet-login-v1` direction and vector package, but does not define or adopt this separate owner-signed site-grant envelope; lifecycle issue [#39](https://github.com/jetpen/decent-ecosystem/issues/39) records a user-confirmed direction and remains open for review. WordPress's OIDC relying-party decision [#2](https://github.com/jetpen/decent-wordpress-auth/issues/2) and browser/session/security decisions [#3–#5](https://github.com/jetpen/decent-wordpress-auth/issues/3) are closed, while its parent spec [#1](https://github.com/jetpen/decent-wordpress-auth/issues/1), implementation [#6](https://github.com/jetpen/decent-wordpress-auth/issues/6), and create/reconnect decision [#9](https://github.com/jetpen/decent-wordpress-auth/issues/9) remain open; those concern the relying-party flow, not adoption of this grant envelope. Storage spec map [#1](https://github.com/jetpen/decent-simple-storage/issues/1) and alignment issue [#18](https://github.com/jetpen/decent-simple-storage/issues/18) remain open; the latter records the narrow role-profile decision, not adoption of this broader envelope. These are protocol/profile review relationships only—not Keycloak runtime, build, or deployment dependencies.

Until the broader decisions above are resolved by their owning projects, the ADR remains Proposed overall. The Storage subsection records the narrow role-only interoperability decision and supersedes the previous Storage profile only; it does not adopt the owner-signed envelope or WordPress decisions, authorize grant implementation, or claim Storage-side or production qualification. Keycloak role-token evidence is limited to the pinned 26.8.0 issuer configuration described in decision 4.
