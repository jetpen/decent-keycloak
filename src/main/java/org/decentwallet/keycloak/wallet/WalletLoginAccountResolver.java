package org.decentwallet.keycloak.wallet;

/** Allows proof acceptance only when one enabled, exact local account is already provisioned. */
@FunctionalInterface
interface WalletLoginAccountResolver {
  boolean hasUniqueEnabledUser(String exactIdentityId) throws Exception;
  default boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) throws Exception {
    return hasUniqueEnabledUser(exactIdentityId);
  }
  default org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) throws Exception {
    return null;
  }
}
