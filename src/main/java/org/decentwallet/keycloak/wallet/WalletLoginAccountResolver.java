package org.decentwallet.keycloak.wallet;

/** Allows proof acceptance only when one enabled, exact local account is already provisioned. */
@FunctionalInterface
interface WalletLoginAccountResolver {
  boolean hasUniqueEnabledUser(String exactIdentityId) throws Exception;
}
