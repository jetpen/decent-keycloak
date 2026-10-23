package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

class Issue7FaultInjectingUserProviderFactoryTest {
  @Test
  void decoratedProviderRetainsCredentialStoreTypeAndDelegatesCredentialCalls() {
    UserProvider jpa = mock(UserProvider.class,
        org.mockito.Mockito.withSettings().extraInterfaces(UserCredentialStore.class));
    UserCredentialStore jpaCredentials = (UserCredentialStore) jpa;
    KeycloakSession session = session(jpa);
    RealmModel realm = mock(RealmModel.class);
    UserModel user = mock(UserModel.class);
    CredentialModel credential = new CredentialModel();
    credential.setId("credential-id");
    when(jpaCredentials.getStoredCredentialById(realm, user, "credential-id")).thenReturn(credential);

    UserProvider decorated = factory("disabled").create(session);

    org.junit.jupiter.api.Assertions.assertInstanceOf(UserCredentialStore.class, decorated);
    UserCredentialStore decoratedCredentials = (UserCredentialStore) decorated;
    assertEquals(credential, decoratedCredentials.getStoredCredentialById(realm, user, "credential-id"));
    verify(jpaCredentials).getStoredCredentialById(realm, user, "credential-id");
  }

  @Test
  void writesAndInitialReadDelegateAndPostCreateExactReadCanReturnEmpty() {
    UserProvider jpa = mock(UserProvider.class);
    KeycloakSession session = session(jpa);
    RealmModel realm = mock(RealmModel.class);
    UserModel created = mock(UserModel.class);
    when(jpa.addUser(realm, null, "signup-user", true, true)).thenReturn(created);
    when(created.getFirstAttribute("decent_identity_id")).thenReturn("identity-value");
    when(jpa.searchForUserByUserAttributeStream(realm, "decent_identity_id", "identity-value"))
        .thenAnswer(ignored -> Stream.empty());

    UserProvider decorated = factory("empty").create(session);
    try (Stream<UserModel> initial = decorated.searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "identity-value")) {
      assertEquals(0, initial.count());
    }
    assertEquals(created, decorated.addUser(realm, null, "signup-user", true, true));
    try (Stream<UserModel> readback = decorated.searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "identity-value")) {
      assertEquals(0, readback.count());
    }

    verify(session).getProvider(UserProvider.class, "jpa");
    verify(jpa).addUser(realm, null, "signup-user", true, true);
    verify(jpa).searchForUserByUserAttributeStream(realm, "decent_identity_id", "identity-value");
  }

  @Test
  void postCreateExactReadCanThrowWithoutAffectingUnrelatedQueries() {
    UserProvider jpa = mock(UserProvider.class);
    KeycloakSession session = session(jpa);
    RealmModel realm = mock(RealmModel.class);
    UserModel created = mock(UserModel.class);
    when(created.getFirstAttribute("decent_identity_id")).thenReturn("identity-value");
    when(jpa.addUser(realm, null, "signup-user", true, true)).thenReturn(created);
    when(jpa.searchForUserByUserAttributeStream(realm, "other", "identity-value"))
        .thenReturn(Stream.empty());

    UserProvider decorated = factory("throw").create(session);
    decorated.addUser(realm, null, "signup-user", true, true);
    assertEquals(0, decorated.searchForUserByUserAttributeStream(realm, "other", "identity-value").count());
    assertThrows(IllegalStateException.class, () -> decorated.searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "identity-value"));
    verify(jpa, never()).searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "identity-value");
    verify(jpa).searchForUserByUserAttributeStream(realm, "other", "identity-value");
  }

  @Test
  void overCapDecoratorEmitsSixtyFiveRowsRepeatingCreatedUserReference() {
    UserProvider jpa = mock(UserProvider.class);
    KeycloakSession session = session(jpa);
    RealmModel realm = mock(RealmModel.class);
    UserModel created = mock(UserModel.class);
    when(created.getFirstAttribute("decent_identity_id")).thenReturn("identity-value");
    when(jpa.addUser(realm, null, "signup-user", true, true)).thenReturn(created);

    UserProvider decorated = factory("over-cap").create(session);
    decorated.addUser(realm, null, "signup-user", true, true);
    var rows = decorated.searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "identity-value").toList();

    assertEquals(65, rows.size());
    assertTrue(rows.stream().allMatch(row -> row == created),
        "the injected response is 65 repeated result rows, not 65 actual users");
    verify(jpa, never()).removeUser(realm, created);
  }

  @Test
  void ensureEnabledUserFailsClosedOnWrapperInjectedOverCapReadAndRetainsCreatedAccount() {
    UserProvider jpa = mock(UserProvider.class);
    KeycloakSession session = session(jpa);
    RealmModel realm = mock(RealmModel.class);
    UserModel created = mock(UserModel.class);
    when(created.getFirstAttribute("decent_identity_id")).thenReturn("identity-value");
    when(created.getId()).thenReturn("created-account-id");
    when(created.isEnabled()).thenReturn(true);
    when(jpa.addUser(eq(realm), eq(null), anyString(), eq(true), eq(true))).thenReturn(created);
    org.mockito.Mockito.when(jpa.searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "identity-value"))
        .thenReturn(Stream.empty(), Stream.of(created));

    UserProvider decorated = factory("over-cap").create(session);
    IllegalStateException failure = assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(
            decorated, realm, "identity-value", true));
    assertTrue(failure.getMessage().contains("identity mapping read-back unavailable"));

    verify(jpa).addUser(eq(realm), eq(null), anyString(), eq(true), eq(true));
    verify(jpa, never()).removeUser(realm, created);
    assertEquals(created, WalletLoginAccountMapping.ensureEnabledUser(
        decorated, realm, "identity-value", false),
        "the subsequent ordinary exact lookup still finds the retained account");
  }

  @Test
  void ensureEnabledUserFailsClosedOnThrowingReadbackAndRecoversRetainedAccount() {
    UserProvider jpa = mock(UserProvider.class);
    KeycloakSession session = session(jpa);
    RealmModel realm = mock(RealmModel.class);
    UserModel created = mock(UserModel.class);
    when(created.getFirstAttribute("decent_identity_id")).thenReturn("identity-value");
    when(created.getId()).thenReturn("created-account-id");
    when(created.isEnabled()).thenReturn(true);
    when(jpa.addUser(eq(realm), eq(null), anyString(), eq(true), eq(true))).thenReturn(created);
    when(jpa.searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "identity-value"))
        .thenReturn(Stream.empty(), Stream.of(created));

    UserProvider decorated = factory("throw").create(session);
    IllegalStateException failure = assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(
            decorated, realm, "identity-value", true));
    assertEquals("IdentityMappingUnavailableException", failure.getClass().getSimpleName());
    assertTrue(failure.getMessage().contains("identity mapping read-back unavailable"));

    verify(jpa).addUser(eq(realm), eq(null), anyString(), eq(true), eq(true));
    verify(jpa, never()).removeUser(realm, created);
    assertEquals(created, WalletLoginAccountMapping.ensureEnabledUser(
        decorated, realm, "identity-value", false),
        "the subsequent ordinary exact lookup still finds the retained account");
    verify(jpa, org.mockito.Mockito.times(2)).searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "identity-value");
  }

  private static KeycloakSession session(UserProvider jpa) {
    KeycloakSession session = mock(KeycloakSession.class);
    when(session.getProvider(UserProvider.class, "jpa")).thenReturn(jpa);
    return session;
  }

  private static Issue7FaultInjectingUserProviderFactory factory(String mode) {
    return new Issue7FaultInjectingUserProviderFactory(mode);
  }

}
