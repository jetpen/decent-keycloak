# Account-action Request Object setup

Issue #68 adds strict separation between legacy wallet-login intent handling and the adopted account-creation actions.

For a client using the adopted flow:

1. Register the RP's public Request Object signing key on the OIDC client, set its Request Object signing algorithm to `ES256`, and require a signed `request` Request Object.
2. Configure a client policy with both Keycloak's built-in `secure-request-object` executor and this provider's `decent-account-request` executor on the `AUTHORIZATION_REQUEST` event. The custom executor is mandatory for account actions; the built-in executor alone does not enforce the complete account-request contract or one-use `jti`.
3. Enable the custom executor's `enabled` configuration property.
4. Put `decent_account_action` (`signup` or `signup_recovery`) and `decent_account_request` inside the signed object, not on the outer query/form. The extension has exactly `profile`, `request_id`, `purpose`, and `claims`; its profile is `decent-account-disclosure-v1`. `request_id` is a 128-bit base64url-no-pad value. Each claim is a distinct registered ID and a JSON boolean `required` flag.
5. Include `iss` and `client_id` exactly equal to the configured RP client ID, the exact realm issuer as scalar `aud`, and integer `iat`/`exp` no more than 300 seconds apart. `jti` is unique and is enforced once per client until expiry.

The executor runs at Keycloak's post-parse, pre-AuthenticationSession-update `AUTHORIZATION_REQUEST` policy seam. Keycloak verifies the signed Request Object with registered client keys before this executor; the executor checks exact issuer/client/audience, the configured ES256 requirement, timestamps, extension shape, and atomic `jti` replay, then records the selected action on the matching AuthenticationSession. The authenticator copies that binding into the pending wallet transaction. An unsigned outer action is rejected and never acts as a selector.

This is an account-action prerequisite only. It does not implement disclosure context, account values, RP-local account checks, Owner-Key binding, or the rest of the account-disclosure flow. Legacy `wallet_intent=signup` remains a separate Issue #7-compatible path and is not `signup_recovery` conformance.
