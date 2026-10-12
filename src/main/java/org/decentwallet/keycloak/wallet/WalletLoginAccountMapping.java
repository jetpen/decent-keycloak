package org.decentwallet.keycloak.wallet;

import java.util.List;
import java.util.stream.Stream;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

/** Exact one-to-one mapping between a Registry identity and an enabled local Keycloak user. */
final class WalletLoginAccountMapping {
  private WalletLoginAccountMapping() {}

  static UserModel findUniqueEnabledUser(UserProvider users, RealmModel realm, String identityId) {
    if (users == null || realm == null || identityId == null || identityId.isEmpty()) return null;
    try (Stream<UserModel> candidates = users.searchForUserByUserAttributeStream(
        realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)) {
      if (candidates == null) return null;
      List<UserModel> matches = candidates
          .filter(java.util.Objects::nonNull)
          .filter(user -> identityId.equals(
              user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)))
          .limit(2)
          .toList();
      if (matches.size() != 1 || !matches.get(0).isEnabled()) return null;
      return matches.get(0);
    }
  }
}
