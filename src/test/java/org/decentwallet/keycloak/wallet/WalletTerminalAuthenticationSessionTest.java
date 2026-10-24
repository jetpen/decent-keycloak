package org.decentwallet.keycloak.wallet;

import java.util.HashMap;
import org.junit.jupiter.api.Test;
import org.infinispan.Cache;
import org.keycloak.models.*;
import org.keycloak.models.sessions.infinispan.*;
import org.keycloak.models.sessions.infinispan.changes.*;
import org.keycloak.models.sessions.infinispan.entities.*;
import org.keycloak.sessions.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Pinned provider/adapter/transaction tasks, not a map-only RootAuthenticationSession mock.
 * Cache transport/commit is deliberately outside this test; merge is replayed on a newer entity.
 */
class WalletTerminalAuthenticationSessionTest {
  private static final String HANDLE = "failed-handle";
  private final KeycloakSession session = mock(KeycloakSession.class);
  private final RealmModel realm = mock(RealmModel.class);
  private final ClientModel client = mock(ClientModel.class);
  private final RootAuthenticationSessionEntity entity = entity();
  private final TestTransaction tx;
  private final InfinispanAuthenticationSessionProvider provider;
  private final RootAuthenticationSessionModel root;
  private final WalletLoginTransactionStore.Binding binding = new WalletLoginTransactionStore.Binding(
      "realm", "client-internal", "root", "failed-tab", "https://rp.example/callback", "https://idp.example");

  @SuppressWarnings("unchecked")
  WalletTerminalAuthenticationSessionTest() {
    var context = mock(KeycloakContext.class);
    when(session.getContext()).thenReturn(context);
    when(context.getRealm()).thenReturn(realm);
    when(session.getTransactionManager()).thenReturn(mock(KeycloakTransactionManager.class));
    var realms = mock(RealmProvider.class);
    when(session.realms()).thenReturn(realms);
    when(realms.getRealm("realm")).thenReturn(realm);
    when(realm.getId()).thenReturn("realm");
    when(realm.getClientById("client-internal")).thenReturn(client);
    when(client.getId()).thenReturn("client-internal");
    when(client.getClientId()).thenReturn("rp-client");
    Cache<String, SessionEntityWrapper<RootAuthenticationSessionEntity>> cache = mock(Cache.class);
    when(cache.get("root")).thenReturn(new SessionEntityWrapper<>(entity));
    tx = new TestTransaction(session, cache);
    provider = spy(new InfinispanAuthenticationSessionProvider(session, tx, 100));
    when(session.authenticationSessions()).thenReturn(provider);
    root = provider.getRootAuthenticationSession(realm, "root");
    var failed = child();
    failed.setRedirectUri(binding.redirectUri());
    failed.getAuthNotes().put("decent.wallet.handle", HANDLE);
    failed.getAuthNotes().put("decent.wallet.client-id", "rp-client");
    failed.getAuthNotes().put("decent.wallet.origin", binding.canonicalOrigin());
    failed.getAuthNotes().put("decent.wallet.redirect_uri", binding.redirectUri());
    entity.getAuthenticationSessions().put("failed-tab", failed);
  }

  @Test void pinnedAdapterSingletonRemovalSchedulesWholeRootRemove() {
    root.removeAuthenticationSessionByTabId("failed-tab");
    verify(provider).removeRootAuthenticationSession(realm, root);
    assertEquals(SessionUpdateTask.CacheOperation.REMOVE, tx.merged().getOperation());
    assertNull(provider.getRootAuthenticationSession(realm, "root"));
  }

  @Test void terminalFailureOnlyMarksSingletonAndDoesNotScheduleRootRemoval() {
    WalletTerminalAuthenticationSession.retire(session, HANDLE, binding);
    assertTrue(entity.getAuthenticationSessions().containsKey("failed-tab"));
    assertNotNull(provider.getRootAuthenticationSession(realm, "root"));
    verify(provider, never()).removeRootAuthenticationSession(any(), any());
    verify(session.getContext(), never()).setAuthenticationSession(any());
    assertNotEquals(SessionUpdateTask.CacheOperation.REMOVE, tx.merged().getOperation());
  }

  @Test void deferredPruneKeepsRealFreshChildAndMergesConcurrentSiblingUpdate() {
    WalletTerminalAuthenticationSession.retire(session, HANDLE, binding);
    tx.clearTasks(); // marker has committed before the fresh browser request
    entity.getAuthenticationSessions().put("unrelated", child());
    var newer = copy(entity); // independent cache version, before this request's creation
    var current = root.createAuthenticationSession(client);
    clearInvocations(session.getContext());
    WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, current);
    assertFalse(entity.getAuthenticationSessions().containsKey("failed-tab"));
    assertTrue(entity.getAuthenticationSessions().containsKey(current.getTabId()));
    assertTrue(entity.getAuthenticationSessions().containsKey("unrelated"));
    verify(provider, never()).removeRootAuthenticationSession(any(), any());
    verify(session.getContext(), never()).setAuthenticationSession(any());

    // Concurrent transaction changed a different child and added another tab after our read.
    newer.getAuthenticationSessions().get("unrelated").getAuthNotes().put("concurrent", "preserved");
    newer.getAuthenticationSessions().put("concurrent-new-tab", child());
    var merged = tx.merged();
    assertEquals(SessionUpdateTask.CacheOperation.REPLACE, merged.getOperation());
    merged.runUpdate(newer);
    assertFalse(merged.shouldRemove(newer));
    assertFalse(newer.getAuthenticationSessions().containsKey("failed-tab"));
    assertTrue(newer.getAuthenticationSessions().containsKey(current.getTabId()));
    assertEquals("preserved", newer.getAuthenticationSessions().get("unrelated").getAuthNotes().get("concurrent"));
    assertTrue(newer.getAuthenticationSessions().containsKey("concurrent-new-tab"));
    WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, current);
    assertTrue(entity.getAuthenticationSessions().containsKey(current.getTabId()));
  }

  @Test void authenticatorPrunesBeforeIssuingFreshChallengeAndNeverCompletesInThatRequest() {
    WalletTerminalAuthenticationSession.retire(session, HANDLE, binding);
    var current = root.createAuthenticationSession(client);
    current.setRedirectUri(binding.redirectUri());
    var context = mock(org.keycloak.authentication.AuthenticationFlowContext.class);
    when(context.getAuthenticationSession()).thenReturn(current);
    when(context.getSession()).thenReturn(session);
    when(context.getRealm()).thenReturn(realm);
    when(realm.getName()).thenReturn("demo");
    when(client.isEnabled()).thenReturn(true);
    when(client.isStandardFlowEnabled()).thenReturn(true);
    when(client.getRedirectUris()).thenReturn(java.util.Set.of(binding.redirectUri()));
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_SITE_LABEL)).thenReturn("Site");
    var uri = mock(KeycloakUriInfo.class);
    when(session.getContext().getUri()).thenReturn(uri);
    when(uri.getBaseUri()).thenReturn(java.net.URI.create("https://idp.example/"));
    var config = mock(AuthenticatorConfigModel.class);
    when(context.getAuthenticatorConfig()).thenReturn(config);
    when(config.getConfig()).thenReturn(java.util.Map.of("trusted-origins", "https://idp.example"));
    var store = mock(WalletLoginTransactionStore.class);
    when(store.issue(any(), eq(WalletLoginTransactionStore.Intent.LOGIN))).thenAnswer(i -> {
      assertFalse(entity.getAuthenticationSessions().containsKey("failed-tab"));
      assertTrue(entity.getAuthenticationSessions().containsKey(current.getTabId()));
      assertNull(current.getAuthNote("decent.wallet.handle"));
      return new WalletLoginTransactionStore.IssuedTransaction("A".repeat(43), "B".repeat(43),
          "C".repeat(43), java.time.Instant.now().plusSeconds(300));
    });
    when(context.generateAccessCode()).thenReturn("code");
    when(context.getActionUrl("code")).thenReturn(java.net.URI.create("https://idp.example/action"));
    var execution = mock(AuthenticationExecutionModel.class);
    when(context.getExecution()).thenReturn(execution);
    when(execution.getId()).thenReturn("execution");
    var form = mock(org.keycloak.forms.login.LoginFormsProvider.class, RETURNS_SELF);
    when(context.form()).thenReturn(form);
    var response = mock(jakarta.ws.rs.core.Response.class);
    when(form.createForm("wallet-login.ftl")).thenReturn(response);
    new WalletChallengeAuthenticator(() -> store).authenticate(context);
    verify(store).issue(any(), eq(WalletLoginTransactionStore.Intent.LOGIN));
    verify(context).challenge(response);
    verify(context, never()).success();
    verify(context, never()).failure(any());
    assertEquals("A".repeat(43), current.getAuthNote("decent.wallet.handle"));
    assertTrue(entity.getAuthenticationSessions().containsKey(current.getTabId()));
    verify(provider, never()).removeRootAuthenticationSession(any(), any());
  }

  @Test void singletonMarkMergeDoesNotDeleteAConcurrentlyAddedSibling() {
    var newer = copy(entity);
    WalletTerminalAuthenticationSession.retire(session, HANDLE, binding);
    newer.getAuthenticationSessions().put("concurrent", child());
    var merged = tx.merged();
    assertEquals(SessionUpdateTask.CacheOperation.REPLACE, merged.getOperation());
    merged.runUpdate(newer);
    assertFalse(merged.shouldRemove(newer));
    assertEquals(2, newer.getAuthenticationSessions().size());
    assertNotNull(newer.getAuthenticationSessions().get("failed-tab").getAuthNotes()
        .get("decent.wallet.terminal-failure"));
  }

  @Test void singletonOrPreviouslyIssuedOrCompletedCurrentIsNotAGuard() {
    WalletTerminalAuthenticationSession.retire(session, HANDLE, binding);
    var failed = root.getAuthenticationSessions().get("failed-tab");
    WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, failed);
    assertTrue(entity.getAuthenticationSessions().containsKey("failed-tab"));
    var current = root.createAuthenticationSession(client);
    current.setAuthNote("decent.wallet.handle", "already-issued");
    WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, current);
    assertTrue(entity.getAuthenticationSessions().containsKey("failed-tab"));
    current.removeAuthNote("decent.wallet.handle");
    current.setClientNote("decent.wallet.callback.completed", "true");
    WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, current);
    assertTrue(entity.getAuthenticationSessions().containsKey("failed-tab"));
    current.removeClientNote("decent.wallet.callback.completed");
    entity.getAuthenticationSessions().remove(current.getTabId());
    WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, current);
    assertTrue(entity.getAuthenticationSessions().containsKey("failed-tab"));
    verify(provider, never()).removeRootAuthenticationSession(any(), any());
  }

  @Test void multipleMarkedChildrenNeverConsumeTheFreshGuardOrCompletedReplaySibling() {
    WalletTerminalAuthenticationSession.retire(session, HANDLE, binding);
    var second = child();
    second.setRedirectUri(binding.redirectUri());
    second.getAuthNotes().putAll(entity.getAuthenticationSessions().get("failed-tab").getAuthNotes());
    second.getAuthNotes().remove("decent.wallet.terminal-failure");
    entity.getAuthenticationSessions().put("second-failed", second);
    var secondBinding = new WalletLoginTransactionStore.Binding(binding.realmId(), binding.clientId(),
        binding.rootSessionId(), "second-failed", binding.redirectUri(), binding.canonicalOrigin());
    WalletTerminalAuthenticationSession.retire(session, HANDLE, secondBinding);
    var completed = child();
    completed.getClientNotes().put("decent.wallet.callback.completed", "true");
    entity.getAuthenticationSessions().put("completed-replay", completed);
    var current = root.createAuthenticationSession(client);
    WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, current);
    assertEquals(java.util.Set.of(current.getTabId(), "completed-replay"),
        entity.getAuthenticationSessions().keySet());
    assertSame(completed, entity.getAuthenticationSessions().get("completed-replay"));
    assertEquals("true", completed.getClientNotes().get("decent.wallet.callback.completed"));
    verify(provider, never()).removeRootAuthenticationSession(any(), any());
  }

  @Test void bindingMutationOrReplacementIsNeverPruned() {
    WalletTerminalAuthenticationSession.retire(session, HANDLE, binding);
    var current = root.createAuthenticationSession(client);
    var failed = entity.getAuthenticationSessions().get("failed-tab");
    for (String key : java.util.List.of("decent.wallet.handle", "decent.wallet.client-id",
        "decent.wallet.origin", "decent.wallet.redirect_uri", "decent.wallet.terminal-failure")) {
      String original = failed.getAuthNotes().put(key, "changed");
      WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, current);
      assertTrue(entity.getAuthenticationSessions().containsKey("failed-tab"), key);
      failed.getAuthNotes().put(key, original);
    }
    failed.setRedirectUri("https://different.example/callback");
    WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, current);
    assertTrue(entity.getAuthenticationSessions().containsKey("failed-tab"));
    entity.getAuthenticationSessions().put("failed-tab", child());
    WalletTerminalAuthenticationSession.pruneOnFreshAuthenticate(realm, current);
    assertTrue(entity.getAuthenticationSessions().containsKey("failed-tab"));
    verify(provider, never()).removeRootAuthenticationSession(any(), any());
  }

  @Test void wrongBindingNeverMarksTheTarget() {
    for (String key : java.util.List.of("decent.wallet.handle", "decent.wallet.client-id",
        "decent.wallet.origin", "decent.wallet.redirect_uri")) {
      var notes = entity.getAuthenticationSessions().get("failed-tab").getAuthNotes();
      String original = notes.put(key, "changed");
      WalletTerminalAuthenticationSession.retire(session, HANDLE, binding);
      assertNull(notes.get("decent.wallet.terminal-failure"));
      notes.put(key, original);
    }
    when(realm.getId()).thenReturn("other-realm");
    WalletTerminalAuthenticationSession.retire(session, HANDLE, binding);
    assertNull(entity.getAuthenticationSessions().get("failed-tab").getAuthNotes()
        .get("decent.wallet.terminal-failure"));
    verify(provider, never()).removeRootAuthenticationSession(any(), any());
  }

  private static RootAuthenticationSessionEntity copy(RootAuthenticationSessionEntity source) {
    var result = entity();
    source.getAuthenticationSessions().forEach((tab, auth) -> {
      var cloned = child();
      cloned.setClientUUID(auth.getClientUUID());
      cloned.setRedirectUri(auth.getRedirectUri());
      cloned.setAuthNotes(new HashMap<>(auth.getAuthNotes()));
      cloned.setClientNotes(new HashMap<>(auth.getClientNotes()));
      result.getAuthenticationSessions().put(tab, cloned);
    });
    return result;
  }

  private static RootAuthenticationSessionEntity entity() {
    var result = new RootAuthenticationSessionEntity("root");
    result.setRealmId("realm");
    return result;
  }

  private static AuthenticationSessionEntity child() {
    var result = new AuthenticationSessionEntity();
    result.setClientUUID("client-internal");
    result.setAuthNotes(new HashMap<>());
    result.setClientNotes(new HashMap<>());
    return result;
  }

  private static final class TestTransaction extends InfinispanChangelogBasedTransaction<String, RootAuthenticationSessionEntity> {
    TestTransaction(KeycloakSession session, Cache<String, SessionEntityWrapper<RootAuthenticationSessionEntity>> cache) {
      super(session, new CacheHolder<>(cache, null, (r, c, e) -> 60000L,
          (r, c, e) -> 60000L, () -> "root", false));
    }
    void clearTasks() { updates.get("root").getUpdateTasks().clear(); }
    MergedUpdate<RootAuthenticationSessionEntity> merged() {
      var list = updates.get("root");
      return MergedUpdate.computeUpdate(list.getUpdateTasks(), list.getEntityWrapper(), 60000L, 60000L);
    }
  }
}
