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
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.Test;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

class Issue7FaultInjectingUserProviderFactoryTest {
  @Test
  void requestCorrelationIsNestedRestoredAndClearedAndMarksExactReadback() {
    String requestId = "1234567890abcdef1234567890abcdef";
    assertTrue(WalletRequestCorrelation.isValidRequestId(requestId));
    for (String invalidRequestId : new String[] {null, "", "1234567890abcdef1234567890abcde", "1234567890abcdef1234567890abcdefg",
        "1234567890abcdef1234567890abcdeG", "1234567890abcdef1234567890abcde-"}) {
      assertTrue(!WalletRequestCorrelation.isValidRequestId(invalidRequestId), "accepted invalid request ID: " + invalidRequestId);
    }
    assertEquals(null, WalletRequestCorrelation.current());
    try (WalletRequestCorrelation.Scope outer = WalletRequestCorrelation.open("a".repeat(32))) {
      assertEquals("a".repeat(32), WalletRequestCorrelation.current());
      try (WalletRequestCorrelation.Scope inner = WalletRequestCorrelation.open(requestId)) {
        assertEquals(requestId, WalletRequestCorrelation.current());
      }
      assertEquals("a".repeat(32), WalletRequestCorrelation.current());
    }
    assertEquals(null, WalletRequestCorrelation.current());

    UserProvider jpa = mock(UserProvider.class);
    KeycloakSession session = session(jpa);
    RealmModel realm = mock(RealmModel.class);
    UserModel created = mock(UserModel.class);
    when(jpa.addUser(realm, null, "signup-user", true, true)).thenReturn(created);
    when(created.getFirstAttribute("decent_identity_id")).thenReturn("identity-value");
    UserProvider decorated = factory("empty").create(session);
    decorated.addUser(realm, null, "signup-user", true, true);
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    PrintStream prior = System.err;
    try (PrintStream replacement = new PrintStream(captured);
        WalletRequestCorrelation.Scope scope = WalletRequestCorrelation.open(requestId)) {
      System.setErr(replacement);
      decorated.searchForUserByUserAttributeStream(realm, "decent_identity_id", "identity-value").count();
    } finally {
      System.setErr(prior);
    }
    String logs = captured.toString(java.nio.charset.StandardCharsets.UTF_8);
    assertEquals(String.join(System.lineSeparator(),
        "ISSUE7_USER_READBACK_OPERATION: provider=issue7-user-readback-fault operation=post_create_exact_attribute_read request=" + requestId,
        "ISSUE7_USER_READBACK_FAULT: provider=issue7-user-readback-fault operation=post_create_exact_attribute_read post-create exact attribute read intercepted request=" + requestId,
        "ISSUE7_USER_READBACK_OUTCOME: provider=issue7-user-readback-fault operation=post_create_exact_attribute_read empty request=" + requestId,
        ""), logs);
    assertEquals(null, WalletRequestCorrelation.current());
    for (String invalidRequestId : new String[] {null, "not-a-request-id"}) {
      UserProvider invalidJpa = mock(UserProvider.class);
      KeycloakSession invalidSession = session(invalidJpa);
      RealmModel invalidRealm = mock(RealmModel.class);
      UserModel invalidCreated = mock(UserModel.class);
      when(invalidJpa.addUser(invalidRealm, null, "signup-user", true, true)).thenReturn(invalidCreated);
      when(invalidCreated.getFirstAttribute("decent_identity_id")).thenReturn("identity-value");
      UserProvider invalidDecorated = factory("empty").create(invalidSession);
      invalidDecorated.addUser(invalidRealm, null, "signup-user", true, true);

      ByteArrayOutputStream invalidCaptured = new ByteArrayOutputStream();
      PrintStream invalidPrior = System.err;
      try (PrintStream replacement = new PrintStream(invalidCaptured);
          WalletRequestCorrelation.Scope scope = WalletRequestCorrelation.open(invalidRequestId)) {
        System.setErr(replacement);
        invalidDecorated.searchForUserByUserAttributeStream(invalidRealm, "decent_identity_id", "identity-value").count();
      } finally {
        System.setErr(invalidPrior);
      }
      assertEquals("", invalidCaptured.toString(java.nio.charset.StandardCharsets.UTF_8));
    }
  }

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
  void overCapDecoratorEmitsSixtyFiveDistinctCandidateIds() {
    UserProvider jpa = mock(UserProvider.class);
    KeycloakSession session = session(jpa);
    RealmModel realm = mock(RealmModel.class);
    UserModel created = mock(UserModel.class);
    when(created.getFirstAttribute("decent_identity_id")).thenReturn("identity-value");
    when(created.getId()).thenReturn("created-account-id");
    when(jpa.addUser(realm, null, "signup-user", true, true)).thenReturn(created);

    UserProvider decorated = factory("over-cap").create(session);
    decorated.addUser(realm, null, "signup-user", true, true);
    var rows = decorated.searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "identity-value").toList();

    assertEquals(65, rows.size());
    assertEquals(65, rows.stream().map(UserModel::getId).distinct().count(),
        "Keycloak's UserStorageManager deduplicates rows by ID before the mapping helper sees them");
    assertTrue(rows.stream().noneMatch(row -> row == created),
        "over-cap rows need distinct synthetic UserModel identities");
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
