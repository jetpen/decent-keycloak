package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

final class WalletLoginAccountMappingTest {
  @Test
  void resolvesOneEnabledExactIdentifierMapping() {
    String identityId = "mailto:Alice@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var user = mock(UserModel.class);
    when(user.isEnabled()).thenReturn(true);
    when(user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE,
        identityId)).thenReturn(Stream.of(user));

    assertEquals(user, WalletLoginAccountMapping.findUniqueEnabledUser(users, realm, identityId));
  }

  @Test
  void rejectsMissingDuplicateAndDisabledMappings() {
    String identityId = "mailto:Alice@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    when(users.searchForUserByUserAttributeStream(realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE,
        identityId)).thenReturn(Stream.empty());
    assertNull(WalletLoginAccountMapping.findUniqueEnabledUser(users, realm, identityId));

    var first = mock(UserModel.class);
    var second = mock(UserModel.class);
    when(first.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(second.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE,
        identityId)).thenReturn(Stream.of(first, second));
    assertNull(WalletLoginAccountMapping.findUniqueEnabledUser(users, realm, identityId));

    when(first.isEnabled()).thenReturn(false);
    when(users.searchForUserByUserAttributeStream(realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE,
        identityId)).thenReturn(Stream.of(first));
    assertNull(WalletLoginAccountMapping.findUniqueEnabledUser(users, realm, identityId));
  }
}
