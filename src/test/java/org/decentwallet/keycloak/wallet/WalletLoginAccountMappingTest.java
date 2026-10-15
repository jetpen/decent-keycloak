package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

final class WalletLoginAccountMappingTest {
  @Test
  void authenticationIntentIsBoundToPendingTransactionNotClientSuppliedProof() {
    boolean implemented = java.util.Arrays.stream(WalletLoginTransactionStore.class.getDeclaredMethods())
        .anyMatch(method -> method.getName().equals("issue")
            && java.util.Arrays.asList(method.getParameterTypes()).contains(WalletLoginTransactionStore.Intent.class));
    org.junit.jupiter.api.Assertions.assertTrue(implemented,
        "signup intent must be carried by the server-bound transaction binding");
  }

  @Test
  void supportsSignupProvisioningThroughASeparateEnsureUserPath() {
    boolean implemented = java.util.Arrays.stream(WalletLoginAccountMapping.class.getDeclaredMethods())
        .anyMatch(method -> method.getName().equals("ensureEnabledUser")
            && java.util.Arrays.asList(method.getParameterTypes()).contains(boolean.class));
    org.junit.jupiter.api.Assertions.assertTrue(implemented,
        "signup intent needs an exact-mapping-or-provision path before nonce consumption");
  }

  @Test
  void signupProvisioningSetsProfileFieldsRequiredByKeycloakProfileBeforeConsumption() {
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var created = mock(UserModel.class);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, "mailto:new@example.org"))
        .thenReturn(Stream.<UserModel>empty(), Stream.of(created));
    when(users.addUser(realm, null,
        "wallet-" + hexDigest("mailto:new@example.org"), true, true)).thenReturn(created);
    when(created.getId()).thenReturn("user-id");
    when(created.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn("mailto:new@example.org");
    when(created.isEnabled()).thenReturn(true);

    assertEquals(created, WalletLoginAccountMapping.ensureEnabledUser(users, realm,
        "mailto:new@example.org", true));

    verify(created).setEmail("wallet-" + hexDigest("mailto:new@example.org").substring(0, 32) + "@example.com");
    verify(created).setFirstName("Wallet");
    verify(created).setLastName("Account");
  }

  private static String hexDigest(String identityId) {
    try {
      return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
          .digest(identityId.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
  }
  @Test
  void signupProvisioningAdoptsConcurrentExactIdentityAccountWhenUsernameCreationLosesRace() {
    String identityId = "mailto:race@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var racedWinner = mock(UserModel.class);
    when(racedWinner.isEnabled()).thenReturn(true);
    when(racedWinner.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(Stream.empty(), Stream.of(racedWinner));
    String username = "wallet-" + hexDigest(identityId);
    when(users.addUser(realm, null, username, true, true))
        .thenThrow(new IllegalStateException("concurrent username insert won"));

    var resolved = WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true);

    assertEquals(racedWinner, resolved);
  }

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
  void booleanMappingLookupUsesTheUniqueAttributeQueryAndClosesItsStream() {
    String identityId = "mailto:Alice@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var user = mock(UserModel.class);
    when(user.isEnabled()).thenReturn(true);
    when(user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)).thenReturn(Stream.of(user));

    org.junit.jupiter.api.Assertions.assertTrue(
        WalletLoginAccountMapping.hasUniqueEnabledMapping(users, realm, identityId));
    verify(users).searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId);
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

    var enabled = mock(UserModel.class);
    var disabled = mock(UserModel.class);
    when(enabled.isEnabled()).thenReturn(true);
    when(disabled.isEnabled()).thenReturn(false);
    when(enabled.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(disabled.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)).thenReturn(Stream.of(enabled, disabled));
    org.junit.jupiter.api.Assertions.assertFalse(
        WalletLoginAccountMapping.hasUniqueMappingIncludingDisabled(users, realm, identityId));
  }
}
