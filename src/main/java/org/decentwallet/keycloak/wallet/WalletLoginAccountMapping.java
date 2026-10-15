package org.decentwallet.keycloak.wallet;

import java.util.List;
import java.util.stream.Stream;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

/** Exact one-to-one mapping between a Registry identity and an enabled local Keycloak user. */
final class WalletLoginAccountMapping {
  private static final int MAX_IDENTITY_CANDIDATES = 64;
  private static final org.jboss.logging.Logger LOG =
      org.jboss.logging.Logger.getLogger(WalletLoginAccountMapping.class);
  private WalletLoginAccountMapping() {}

  static UserModel findUniqueEnabledUser(UserProvider users, RealmModel realm, String identityId) {
    return ensureEnabledUser(users, realm, identityId, false);
  }

  static UserModel ensureEnabledUser(UserProvider users, RealmModel realm, String identityId,
      boolean createIfMissing) {
    if (users == null || realm == null || identityId == null || identityId.isEmpty()) return null;
    List<UserModel> matches;
    try (Stream<UserModel> candidates = users.searchForUserByUserAttributeStream(
        realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)) {
      if (candidates == null) return null;
      List<UserModel> scan = candidates
          .filter(java.util.Objects::nonNull)
          .limit(MAX_IDENTITY_CANDIDATES + 1)
          .toList();
      if (scan.size() > MAX_IDENTITY_CANDIDATES) return null;
      matches = scan.stream()
          .filter(user -> identityId.equals(
              user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)))
          .limit(2)
          .toList();
    }
    if (matches.size() == 1 && matches.getFirst().isEnabled()) return matches.getFirst();
    if (!createIfMissing || !matches.isEmpty()) return null;
    String username;
    try {
      username = "wallet-" + java.util.HexFormat.of().formatHex(
          java.security.MessageDigest.getInstance("SHA-256")
              .digest(identityId.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("SHA-256 unavailable", impossible);
    }
    UserModel created;
    try {
      created = users.addUser(realm, null, username, true, true);
    } catch (RuntimeException concurrentUsernameCreation) {
      // A concurrent request for the same exact identity may already have
      // inserted the deterministic username and mapping. Adopt only after an
      // independent exact-ID read proves there is one enabled winner.
      try (Stream<UserModel> rechecked = users.searchForUserByUserAttributeStream(
          realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)) {
        if (rechecked == null) return null;
        List<UserModel> exactMatches = rechecked.filter(java.util.Objects::nonNull)
            .filter(user -> identityId.equals(
                user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)))
            .limit(2).toList();
        return exactMatches.size() == 1 && exactMatches.getFirst().isEnabled()
            ? exactMatches.getFirst() : null;
      }
    }
    if (created == null) return null;
    try {
      created.setSingleAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId);
      created.setEnabled(true);
      if (createIfMissing) {
        created.setEmail("wallet-" + username.substring("wallet-".length(), "wallet-".length() + 32)
            + "@example.com");
        created.setFirstName("Wallet");
        created.setLastName("Account");
      }
      try (Stream<UserModel> rechecked = users.searchForUserByUserAttributeStream(
          realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)) {
        if (rechecked == null) throw new IllegalStateException("identity mapping read-back unavailable");
        List<UserModel> exactMatches = rechecked
            .filter(java.util.Objects::nonNull)
            .filter(user -> identityId.equals(
                user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)))
            .limit(2)
            .toList();
        if (exactMatches.size() != 1 || !exactMatches.getFirst().isEnabled()
            || !created.getId().equals(exactMatches.getFirst().getId())) {
          users.removeUser(realm, created);
          return null;
        }
        return exactMatches.getFirst();
      }
    } catch (RuntimeException failure) {
      try { users.removeUser(realm, created); } catch (RuntimeException ignored) { }
      throw failure;
    }
  }

  static boolean hasUniqueEnabledMapping(UserProvider users, RealmModel realm, String identityId) {
    return ensureEnabledUser(users, realm, identityId, false) != null;
  }

  static boolean hasUniqueMappingIncludingDisabled(UserProvider users, RealmModel realm, String identityId) {
    if (users == null || realm == null || identityId == null || identityId.isEmpty()) return false;
    try (Stream<UserModel> candidates = users.searchForUserByUserAttributeStream(
        realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)) {
      if (candidates == null) return false;
      List<UserModel> scan = candidates.filter(java.util.Objects::nonNull)
          .limit(MAX_IDENTITY_CANDIDATES + 1).toList();
      if (scan.size() > MAX_IDENTITY_CANDIDATES) {
        LOG.debug("Wallet account mapping lookup failed closed at candidate cap");
        return false;
      }
      return scan.stream()
          .filter(user -> identityId.equals(
              user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)))
          .limit(2).count() == 1;
    }
  }
}
