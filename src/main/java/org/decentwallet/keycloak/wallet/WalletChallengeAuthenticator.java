package org.decentwallet.keycloak.wallet;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;


/** Starts a browser-bound wallet challenge and resumes only its original Keycloak flow. */
public final class WalletChallengeAuthenticator implements Authenticator {
  private static final org.jboss.logging.Logger LOG =
      org.jboss.logging.Logger.getLogger(WalletChallengeAuthenticator.class);
  private static final String TRUSTED_ORIGINS = "trusted-origins";
  static final String IDENTITY_ATTRIBUTE = "decent_identity_id";
  private final java.util.function.Supplier<WalletLoginTransactionStore> transactionStores;

  public WalletChallengeAuthenticator() {
    this(() -> null);
  }

  WalletChallengeAuthenticator(java.util.function.Supplier<WalletLoginTransactionStore> transactionStores) {
    this.transactionStores = transactionStores;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    WalletLoginTransactionStore store = transactionStores.get();
    if (store == null) {
      failClosed(context);
      return;
    }
    try {
      var auth = context.getAuthenticationSession();
      var authSession = auth;
      var client = authSession == null ? null : authSession.getClient();
      var realm = context.getRealm();
      if (authSession == null || client == null || realm == null || !client.isEnabled()
          || !client.isStandardFlowEnabled()) {
        failClosed(context);
        return;
      }
      String redirectUri = authSession.getRedirectUri();
      if (!isSingleExactHttpsRedirect(client.getRedirectUris(), redirectUri)) {
        failClosed(context);
        return;
      }
      String configuredOrigins = context.getAuthenticatorConfig() == null
          ? null : context.getAuthenticatorConfig().getConfig().get(TRUSTED_ORIGINS);
      java.net.URI base = context.getSession().getContext().getUri().getBaseUri();
      String baseOrigin = base.getScheme() + "://" + base.getRawAuthority();
      String origin = canonicalOrigin(baseOrigin, configuredOrigins);
      String rootSessionId = authSession.getParentSession().getId();
      String tabId = authSession.getTabId();
      if (rootSessionId == null || tabId == null) {
        failClosed(context);
        return;
      }
      var binding = new WalletLoginTransactionStore.Binding(
          realm.getId(), client.getId(), rootSessionId, tabId, redirectUri, origin);
      var issued = store.issue(binding);
      auth.setAuthNote("decent.wallet.handle", issued.handle());
      auth.setAuthNote("decent.wallet.client-id", client.getClientId());
      auth.setAuthNote("decent.wallet.origin", origin);
      auth.setAuthNote("decent.wallet.redirect_uri", redirectUri);
      var callback = context.getRefreshExecutionUrl();
      if (callback == null) throw new IllegalStateException("Keycloak execution callback unavailable");
      auth.setAuthNote("decent.wallet.callback", callback.toASCIIString());
      String resourceRoot = "realms/" + context.getRealm().getName() + "/"
          + WalletLoginTransportResourceFactory.ID + "/v1/transactions";
      String statusQuery = "?client_id=" + java.net.URLEncoder.encode(client.getClientId(),
          java.nio.charset.StandardCharsets.UTF_8) + "&tab_id=" + java.net.URLEncoder.encode(tabId,
          java.nio.charset.StandardCharsets.UTF_8);
      java.net.URI statusUri = base.resolve(resourceRoot + "/" + issued.handle() + "/status" + statusQuery);
      var response = context.form()
          .setAuthenticationSession(authSession)
          .setClientSessionCode(context.generateAccessCode())
          .setExecution(context.getExecution().getId())
          .setAuthContext(context)
          .setActionUri(callback)
          .setAttribute("walletQrDataUri", WalletQrCode.svgDataUri(
              WalletLoginLocator.create(issued.handle(), base, context.getRealm().getName())))
          .setAttribute("walletHandle", issued.handle())
          .setAttribute("walletChallenge", issued.challenge())
          .setAttribute("walletCsrfToken", issued.csrfToken())
          .setAttribute("walletStatusUri", statusUri.toASCIIString())
          .setAttribute("walletChallengeLocator", WalletLoginLocator.create(issued.handle(), base, context.getRealm().getName()))
          .setAttribute("walletOriginLabel", origin)
          .setAttribute("walletExpiresAt", issued.expiresAt().toString())
          .setResponseHeader("Cache-Control", "no-store")
          .setResponseHeader("Referrer-Policy", "no-referrer")
          .createForm("wallet-login.ftl");
      context.challenge(response);
    } catch (RuntimeException failure) {
      failClosed(context);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    // The wallet POST resolved the current Identity key before nonce consumption.
    // This callback consumes the accepted receipt and re-checks the local mapping.
    try {
      var auth = context.getAuthenticationSession();
      if (auth == null || auth.getClient() == null || auth.getParentSession() == null) {
        failClosed(context); return;
      }
      String handle = auth.getAuthNote("decent.wallet.handle");
      if (handle == null) { failClosed(context); return; }
      WalletLoginTransactionStore store = transactionStores.get();
      if (store == null) { failClosed(context); return; }
      var binding = new WalletLoginTransactionStore.Binding(context.getRealm().getId(),
          auth.getClient().getId(), auth.getParentSession().getId(), auth.getTabId(),
          auth.getRedirectUri(), auth.getAuthNote("decent.wallet.origin"));
      var visibleReceipt = store.getAccepted(handle, binding);
      if (visibleReceipt.isEmpty()) { failClosed(context); return; }
      // Resolve mapping before consuming the callback gate so a missing or
      // temporarily unavailable user does not strand the accepted receipt.
      UserModel user = WalletLoginAccountMapping.findUniqueEnabledUser(
          context.getSession().users(), context.getRealm(), visibleReceipt.get().identityId());
      if (user == null || !user.isEnabled()) { failClosed(context); return; }
      // Set the already-validated user before the one-use gate; failures here
      // leave the callback retryable and never mark the authentication execution successful.
      auth.setAuthenticatedUser(user);
      var receipt = store.takeAccepted(handle, binding);
      if (receipt.isEmpty() || !receipt.get().equals(visibleReceipt.get())) { failClosed(context); return; }
      context.success();
      clearWalletAuthNotes(auth);
    } catch (Exception failure) {
      failClosed(context);
    }
  }

  static boolean isSingleExactHttpsRedirect(java.util.Set<String> redirectUris, String activeRedirect) {
    if (redirectUris == null || redirectUris.size() != 1 || activeRedirect == null
        || !redirectUris.contains(activeRedirect) || activeRedirect.indexOf('*') >= 0) return false;
    try {
      java.net.URI uri = java.net.URI.create(activeRedirect);
      return uri.isAbsolute() && "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null
          && uri.getRawAuthority() != null && !uri.getRawAuthority().contains("@")
          && uri.getRawFragment() == null;
    } catch (IllegalArgumentException invalidRedirect) {
      return false;
    }
  }

  private static String canonicalOrigin(String baseOrigin, String configuredOrigins) {
    if (configuredOrigins == null || configuredOrigins.isBlank()) {
      throw new IllegalArgumentException("trusted wallet-login origins are not configured");
    }
    java.net.URI base = java.net.URI.create(baseOrigin);
    if (!"https".equalsIgnoreCase(base.getScheme()) || base.getHost() == null) {
      throw new IllegalArgumentException("Keycloak base URL must be HTTPS");
    }
    String selected = null;
    for (String item : configuredOrigins.split(",")) {
      String candidate = item.trim();
      if (candidate.isEmpty()) continue;
      java.net.URI uri = java.net.URI.create(candidate);
      if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
          || uri.getRawAuthority().contains("@") || uri.getRawPath() != null && !uri.getRawPath().isEmpty()
          || uri.getRawQuery() != null || uri.getRawFragment() != null) {
        throw new IllegalArgumentException("trusted origin entries must be exact HTTPS origins");
      }
      String normalized = "https://" + uri.getRawAuthority().toLowerCase(java.util.Locale.ROOT);
      if (normalized.equals("https://" + base.getRawAuthority().toLowerCase(java.util.Locale.ROOT))) selected = normalized;
    }
    if (selected == null) throw new IllegalArgumentException("Keycloak HTTPS origin is not allowlisted");
    return selected;
  }

  private static void clearWalletAuthNotes(org.keycloak.sessions.AuthenticationSessionModel auth) {
    for (String note : java.util.List.of("decent.wallet.handle", "decent.wallet.client-id",
        "decent.wallet.origin", "decent.wallet.redirect_uri", "decent.wallet.callback")) {
      try { auth.removeAuthNote(note); }
      catch (RuntimeException cleanupFailure) { LOG.warn("Unable to clear a completed wallet-login auth note"); }
    }
  }

  private static void failClosed(AuthenticationFlowContext context) {
    context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return false;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // User enrollment cannot replace a fresh wallet challenge.
  }

  @Override
  public void close() {}
}
