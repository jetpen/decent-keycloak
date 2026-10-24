package org.decentwallet.keycloak.wallet;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/** Defers exact terminal-child retirement until a fresh, retained browser flow exists. */
final class WalletTerminalAuthenticationSession {
  private static final String TERMINAL = "decent.wallet.terminal-failure";
  private static final String HANDLE = "decent.wallet.handle";
  private static final String COMPLETED = "decent.wallet.callback.completed";

  private WalletTerminalAuthenticationSession() {}

  /** Called only after consume won and accepted-receipt publication failed. Never removes a tab. */
  static void retire(KeycloakSession session, String handle,
      WalletLoginTransactionStore.Binding binding) {
    var realm = session.getContext().getRealm();
    if (realm == null || !binding.realmId().equals(realm.getId())) return;
    var client = realm.getClientById(binding.clientId());
    if (client == null) return;
    var root = session.authenticationSessions().getRootAuthenticationSession(realm,
        binding.rootSessionId());
    if (root == null || !binding.rootSessionId().equals(root.getId())) return;
    // getAuthenticationSession(client, tab) changes the request's current session in Keycloak.
    var auth = root.getAuthenticationSessions().get(binding.tabId());
    if (!matches(auth, handle, binding, client.getClientId())) return;
    auth.setAuthNote(TERMINAL, marker(handle, binding, client.getClientId()));
  }

  /** Invoke only while authenticate is preparing a fresh challenge, before issuing its handle.
   * The current child is the retained guard: it cannot complete until a later browser action.
   * Arbitrary siblings are NOT guards; they may finish concurrently. Never create a placeholder.
   */
  static void pruneOnFreshAuthenticate(RealmModel realm, AuthenticationSessionModel current) {
    if (realm == null || !fresh(current) || current.getParentSession() == null) return;
    var root = current.getParentSession();
    if (root.getRealm() == null || !realm.getId().equals(root.getRealm().getId())) return;
    for (String tab : root.getAuthenticationSessions().keySet()) {
      if (tab.equals(current.getTabId())) continue;
      var tabs = root.getAuthenticationSessions();
      var guard = tabs.get(current.getTabId());
      if (!fresh(guard) || guard.getClient() == null || current.getClient() == null
          || !Objects.equals(guard.getClient().getId(), current.getClient().getId())) return;
      var target = tabs.get(tab);
      if (target == null || target.getClient() == null || target.getAuthNote(TERMINAL) == null) continue;
      String handle = target.getAuthNote(HANDLE);
      String origin = target.getAuthNote("decent.wallet.origin");
      String redirect = target.getAuthNote("decent.wallet.redirect_uri");
      if (handle == null || origin == null || redirect == null) continue;
      var binding = new WalletLoginTransactionStore.Binding(realm.getId(), target.getClient().getId(),
          root.getId(), tab, redirect, origin);
      String clientId = target.getClient().getClientId();
      if (!matches(target, handle, binding, clientId)
          || !marker(handle, binding, clientId).equals(target.getAuthNote(TERMINAL))) continue;
      // Keycloak 26.8 removes the entire root for a last child. The fresh current
      // child must still exist here and remains pending for the rest of this request.
      root.removeAuthenticationSessionByTabId(tab);
    }
  }

  private static boolean fresh(AuthenticationSessionModel auth) {
    return auth != null && auth.getTabId() != null && auth.getAuthNote(HANDLE) == null
        && auth.getAuthNote(TERMINAL) == null && auth.getClientNote(COMPLETED) == null;
  }

  private static boolean matches(AuthenticationSessionModel auth, String handle,
      WalletLoginTransactionStore.Binding binding, String clientId) {
    return auth != null && handle != null && clientId != null
        && auth.getClient() != null && auth.getParentSession() != null
        && binding.clientId().equals(auth.getClient().getId())
        && binding.rootSessionId().equals(auth.getParentSession().getId())
        && binding.tabId().equals(auth.getTabId())
        && handle.equals(auth.getAuthNote(HANDLE))
        && clientId.equals(auth.getAuthNote("decent.wallet.client-id"))
        && binding.canonicalOrigin().equals(auth.getAuthNote("decent.wallet.origin"))
        && binding.redirectUri().equals(auth.getAuthNote("decent.wallet.redirect_uri"))
        && binding.redirectUri().equals(auth.getRedirectUri())
        && auth.getClientNote(COMPLETED) == null;
  }

  private static String marker(String handle, WalletLoginTransactionStore.Binding binding, String clientId) {
    // Length framing binds the marker to all validated values, even if a value contains delimiters.
    return List.of(handle, binding.realmId(), binding.clientId(), binding.rootSessionId(),
        binding.tabId(), binding.redirectUri(), binding.canonicalOrigin(), clientId).stream()
        .map(value -> value.length() + ":" + value).collect(Collectors.joining());
  }
}
