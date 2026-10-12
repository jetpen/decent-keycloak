package org.decentwallet.keycloak.wallet;

/** Current exact-match Identity binding resolver; Registry/Identity outage is a fail-closed exception. */
@FunctionalInterface
public interface WalletIdentityKeyResolver {
  ResolvedIdentityKey resolveExact(String identityId) throws Exception;

  record ResolvedIdentityKey(String identityId, byte[] publicKey) {
    public ResolvedIdentityKey {
      if (identityId == null) throw new IllegalArgumentException("identity identifier is required");
      publicKey = publicKey == null ? null : publicKey.clone();
    }
    @Override public byte[] publicKey() { return publicKey == null ? null : publicKey.clone(); }
  }
}
