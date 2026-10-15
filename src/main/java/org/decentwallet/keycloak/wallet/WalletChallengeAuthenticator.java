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
  private static final String SIGNUP_INTENT_ATTRIBUTE = "decent_wallet_signup_intent";
  private static final String SIGNUP_AUTH_NOTE = "decent.wallet.intent";
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
      if (authSession == null) {
        failClosed(context);
        return;
      }
      boolean signupIntent = "signup".equals(authSession.getClientNote(SIGNUP_AUTH_NOTE));
      if (signupIntent) authSession.removeClientNote(SIGNUP_AUTH_NOTE);
      if (signupIntent) authSession.setAuthNote(SIGNUP_AUTH_NOTE, "signup");
      if (signupIntent && !context.getRealm().isRegistrationAllowed()) {
        failClosed(context);
        return;
      }
      var client = authSession.getClient();
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
      if (configuredOrigins == null || configuredOrigins.isBlank()
          || configuredOrigins.split(",").length != 1) {
        throw new IllegalArgumentException("one trusted HTTPS origin must be configured");
      }
      String siteName = realm.getAttribute(WalletLoginTransportResourceFactory.KEY_SITE_LABEL);
      java.net.URI base = context.getSession().getContext().getUri().getBaseUri();
      String origin = canonicalOrigin(base, configuredOrigins);
      if (siteName == null || siteName.isBlank()) {
        failClosed(context);
        return;
      }
      String rootSessionId = authSession.getParentSession().getId();
      String tabId = authSession.getTabId();
      if (rootSessionId == null || tabId == null) {
        failClosed(context);
        return;
      }
      var binding = new WalletLoginTransactionStore.Binding(
          realm.getId(), client.getId(), rootSessionId, tabId, redirectUri, origin);
      var issued = store.issue(binding, signupIntent
          ? WalletLoginTransactionStore.Intent.SIGNUP : WalletLoginTransactionStore.Intent.LOGIN);
      auth.setAuthNote("decent.wallet.handle", issued.handle());
      auth.setAuthNote("decent.wallet.client-id", client.getClientId());
      auth.setAuthNote("decent.wallet.origin", origin);
      auth.setAuthNote("decent.wallet.redirect_uri", redirectUri);
      String accessCode = context.generateAccessCode();
      auth.setAction(org.keycloak.sessions.AuthenticationSessionModel.Action.AUTHENTICATE.name());
      auth.setAuthNote(org.keycloak.authentication.AuthenticationProcessor.CURRENT_FLOW_PATH,
          org.keycloak.services.resources.LoginActionsService.AUTHENTICATE_PATH);
      var callback = context.getActionUrl(accessCode);
      if (callback == null) throw new IllegalStateException("Keycloak execution callback unavailable");
      auth.setAuthNote("decent.wallet.callback", callback.toASCIIString());
      String resourceRoot = "realms/" + context.getRealm().getName() + "/"
          + WalletLoginTransportResourceFactory.ID + "/v1/transactions";
      String statusQuery = "?client_id=" + java.net.URLEncoder.encode(client.getClientId(),
          java.nio.charset.StandardCharsets.UTF_8) + "&tab_id=" + java.net.URLEncoder.encode(tabId,
          java.nio.charset.StandardCharsets.UTF_8);
      java.net.URI statusUri = base.resolve(resourceRoot + "/" + issued.handle() + "/status"
          + statusQuery);
      var response = context.form()
          .setAuthenticationSession(authSession)
          .setClientSessionCode(accessCode)
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
          .setAttribute("walletSiteLabel", siteName.trim())
          .setAttribute("walletExpiresAt", issued.expiresAt().toString())
          .setAttribute("walletIntent", signupIntent ? "signup" : "login")
          .setResponseHeader("Cache-Control", "no-store")
          .setResponseHeader("Referrer-Policy", "no-referrer")
          .createForm("wallet-login.ftl");
      context.challenge(response);
    } catch (RuntimeException failure) {
      LOG.error("Wallet challenge rendering failed", failure);
      failClosed(context);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    var initialAuthSession = context.getAuthenticationSession();
    if (initialAuthSession != null && context.getHttpRequest() != null
        && "POST".equals(context.getHttpRequest().getHttpMethod())
        && context.getHttpRequest().getDecodedFormParameters().containsKey("wallet_intent")) {
      var values = context.getHttpRequest().getDecodedFormParameters().get("wallet_intent");
      if (values != null && values.size() == 1 && "signup".equals(values.getFirst())) {
        initialAuthSession.setClientNote(SIGNUP_AUTH_NOTE, "signup");
        context.resetFlow(() -> initialAuthSession.setClientNote(SIGNUP_AUTH_NOTE, "signup"));
        return;
      }
      failClosed(context);
      return;
    }
    if (context.getAuthenticationSession() != null
        && "true".equals(context.getAuthenticationSession().getAuthNote("decent.wallet.user-provisioned"))
        && context.getUser() != null) {
      try {
        context.getSession().users().removeUser(context.getRealm(), context.getUser());
      } catch (RuntimeException rollbackFailure) {
        LOG.warn("Signup cleanup after callback failure was incomplete");
      } finally {
        context.getAuthenticationSession().removeAuthNote("decent.wallet.user-provisioned");
      }
    }
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
      if (user == null && visibleReceipt.get().intent() == WalletLoginTransactionStore.Intent.SIGNUP
          && context.getRealm().isRegistrationAllowed()) {
        user = WalletLoginAccountMapping.ensureEnabledUser(context.getSession().users(), context.getRealm(),
            visibleReceipt.get().identityId(), true);
        if (user != null) auth.setAuthNote("decent.wallet.user-provisioned", "true");
      }
      if (user == null || !user.isEnabled()) { failClosed(context); return; }
      if (visibleReceipt.get().intent() == WalletLoginTransactionStore.Intent.SIGNUP) {
        if (!WalletLoginAccountMapping.hasUniqueEnabledMapping(context.getSession().users(),
            context.getRealm(), visibleReceipt.get().identityId())) {
          if ("true".equals(auth.getAuthNote("decent.wallet.user-provisioned"))) {
            context.getSession().users().removeUser(context.getRealm(), user);
            auth.removeAuthNote("decent.wallet.user-provisioned");
          }
          failClosed(context);
          return;
        }
      }
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

  private static String canonicalOrigin(java.net.URI base, String configuredOrigins) {
    if (configuredOrigins == null || configuredOrigins.isBlank()) {
      throw new IllegalArgumentException("trusted wallet-login origins are not configured");
    }
    String baseOrigin = WalletLoginTransportHandler.normalizeOrigin(
        base.getScheme() + "://" + base.getRawAuthority());
    boolean allowlisted = java.util.Arrays.stream(configuredOrigins.split(","))
        .map(String::trim)
        .filter(candidate -> !candidate.isEmpty())
        .map(WalletLoginTransportHandler::normalizeOrigin)
        .anyMatch(baseOrigin::equals);
    if (!allowlisted) throw new IllegalArgumentException("Keycloak HTTPS origin is not allowlisted");
    return baseOrigin;
  }

  private static void clearWalletAuthNotes(org.keycloak.sessions.AuthenticationSessionModel auth) {
    for (String note : java.util.List.of("decent.wallet.handle", "decent.wallet.client-id",
        "decent.wallet.origin", "decent.wallet.redirect_uri", "decent.wallet.callback",
        "decent.wallet.intent", "decent.wallet.user-provisioned")) {
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
