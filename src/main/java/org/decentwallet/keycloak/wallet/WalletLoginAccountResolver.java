package org.decentwallet.keycloak.wallet;

/** Allows proof acceptance only when one enabled, exact local account is already provisioned. */
@FunctionalInterface
interface WalletLoginAccountResolver {
  enum Lookup { ENABLED, ABSENT, DISABLED, AMBIGUOUS, UNAVAILABLE }
  boolean hasUniqueEnabledUser(String exactIdentityId) throws Exception;
  default boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) throws Exception {
    return hasUniqueEnabledUser(exactIdentityId);
  }
  default Lookup lookupExact(String exactIdentityId) throws Exception {
    if (hasUniqueEnabledUser(exactIdentityId)) return Lookup.ENABLED;
    return hasUniqueMappedUserIncludingDisabled(exactIdentityId) ? Lookup.AMBIGUOUS : Lookup.ABSENT;
  }
  default org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) throws Exception {
    return null;
  }
}
