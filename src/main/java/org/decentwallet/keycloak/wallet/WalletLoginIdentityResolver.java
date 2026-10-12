package org.decentwallet.keycloak.wallet;

/** Makes exact current-Identity resolution available to the auth-session owner. */
@FunctionalInterface
interface WalletLoginIdentityResolver {
  WalletIdentityKeyResolver.ResolvedIdentityKey resolveExact(String identityId) throws Exception;
}
