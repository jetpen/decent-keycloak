package org.decentwallet.keycloak.wallet;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

final class WalletChallengeAuthenticatorTest {
  @Test
  void browserLoginFormHasExplicitSignupChoice() throws Exception {
    try {
      java.nio.file.Path templatePath = java.nio.file.Path.of(
          "src/main/resources/theme-resources/templates/wallet-login.ftl");
      var template = java.nio.file.Files.readString(templatePath);
      assertTrue(template.contains("walletIntent"));
      assertTrue(template.contains("Create account with wallet"));
    } catch (java.io.IOException failure) {
      throw new AssertionError("wallet login template is readable", failure);
    }
  }

  @Test
  void authenticateRendersWalletChallengeAndStoresPendingTransaction() {
    var transactionStore = mock(WalletLoginTransactionStore.class);
    var authenticator = new WalletChallengeAuthenticator(() -> transactionStore);
    var context = mock(AuthenticationFlowContext.class);
    var session = mock(org.keycloak.models.KeycloakSession.class);
    var keycloakContext = mock(org.keycloak.models.KeycloakContext.class);
    var uriInfo = mock(org.keycloak.models.KeycloakUriInfo.class);
    var rootSession = mock(org.keycloak.sessions.RootAuthenticationSessionModel.class);
    var authSession = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
    var client = mock(org.keycloak.models.ClientModel.class);
    var realm = mock(org.keycloak.models.RealmModel.class);
    var form = mock(org.keycloak.forms.login.LoginFormsProvider.class);
    var response = mock(jakarta.ws.rs.core.Response.class);

    org.mockito.Mockito.when(context.getSession()).thenReturn(session);
    org.mockito.Mockito.when(context.getAuthenticationSession()).thenReturn(authSession);
    org.mockito.Mockito.when(context.getHttpRequest()).thenReturn(mock(org.keycloak.http.HttpRequest.class));
    org.mockito.Mockito.when(authSession.getClientNote("prompt")).thenReturn(null);
    org.mockito.Mockito.when(authSession.getClientNote("decent.wallet.intent")).thenReturn(null);
    org.mockito.Mockito.when(authSession.getAuthNote("decent.wallet.intent")).thenReturn(null);
    org.mockito.Mockito.when(context.getRealm()).thenReturn(realm);
    org.mockito.Mockito.when(context.form()).thenReturn(form);
    org.mockito.Mockito.when(session.getContext()).thenReturn(keycloakContext);
    org.mockito.Mockito.when(session.singleUseObjects()).thenReturn(mock(org.keycloak.models.SingleUseObjectProvider.class));
    org.mockito.Mockito.when(keycloakContext.getUri()).thenReturn(uriInfo);
    org.mockito.Mockito.when(uriInfo.getBaseUri()).thenReturn(URI.create("https://idp.example:18886/auth/"));
    org.mockito.Mockito.when(realm.getId()).thenReturn("realm-id");
    org.mockito.Mockito.when(realm.getName()).thenReturn("demo");
    org.mockito.Mockito.when(client.getClientId()).thenReturn("client-public");
    org.mockito.Mockito.when(authSession.getClient()).thenReturn(client);
    org.mockito.Mockito.when(authSession.getParentSession()).thenReturn(rootSession);
    org.mockito.Mockito.when(rootSession.getId()).thenReturn("root-session-id");
    org.mockito.Mockito.when(authSession.getTabId()).thenReturn("tab-id");
    org.mockito.Mockito.when(client.getId()).thenReturn("client-id");
    org.mockito.Mockito.when(client.isEnabled()).thenReturn(true);
    org.mockito.Mockito.when(client.isStandardFlowEnabled()).thenReturn(true);
    org.mockito.Mockito.when(client.getRedirectUris()).thenReturn(Set.of("https://site.example/callback"));
    org.mockito.Mockito.when(authSession.getRedirectUri()).thenReturn("https://site.example/callback");
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_SITE_LABEL))
        .thenReturn("Realm Relying Party");
    Map<String, String> configured = Map.of("trusted-origins", "https://idp.example:18886");
    var authenticatorConfig = mock(org.keycloak.models.AuthenticatorConfigModel.class);
    org.mockito.Mockito.when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
    when(authenticatorConfig.getConfig()).thenReturn(configured);
    org.mockito.Mockito.when(context.getActionUrl("access-code")).thenReturn(URI.create("https://idp.example:18886/auth/realms/demo/login-actions/authenticate?session_code=access-code&execution=exec&client_id=client&tab_id=tab"));
    org.mockito.Mockito.when(context.generateAccessCode()).thenReturn("access-code");
    var execution = mock(org.keycloak.models.AuthenticationExecutionModel.class);
    org.mockito.Mockito.when(context.getExecution()).thenReturn(execution);
    org.mockito.Mockito.when(execution.getId()).thenReturn("execution-id");
    var issued = new WalletLoginTransactionStore.IssuedTransaction("A".repeat(43), "B".repeat(43), "C".repeat(43), Instant.now().plusSeconds(300));
    org.mockito.Mockito.when(transactionStore.issue(org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(WalletLoginTransactionStore.Intent.LOGIN))).thenReturn(issued);
    org.mockito.Mockito.when(transactionStore.issue(org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(WalletLoginTransactionStore.Intent.SIGNUP))).thenReturn(issued);
    org.mockito.Mockito.when(form.setAuthenticationSession(authSession)).thenReturn(form);
    org.mockito.Mockito.when(form.setClientSessionCode(org.mockito.ArgumentMatchers.anyString())).thenReturn(form);
    org.mockito.Mockito.when(form.setExecution(org.mockito.ArgumentMatchers.anyString())).thenReturn(form);
    org.mockito.Mockito.when(form.setAuthContext(context)).thenReturn(form);
    org.mockito.Mockito.when(form.setActionUri(org.mockito.ArgumentMatchers.any(URI.class))).thenReturn(form);
    org.mockito.Mockito.when(form.setResponseHeader(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString())).thenReturn(form);
    org.mockito.Mockito.when(form.setAttribute(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(form);
    org.mockito.Mockito.when(form.createForm("wallet-login.ftl")).thenReturn(response);

    authenticator.authenticate(context);

    org.mockito.Mockito.verify(transactionStore).issue(org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(WalletLoginTransactionStore.Intent.LOGIN));
    org.mockito.Mockito.verify(context).challenge(response);
    org.mockito.Mockito.verify(form).setResponseHeader("Cache-Control", "no-store");
    org.mockito.Mockito.verify(form).setResponseHeader("Referrer-Policy", "no-referrer");
    var locator = org.mockito.ArgumentCaptor.forClass(String.class);
    org.mockito.Mockito.verify(form).setAttribute(org.mockito.ArgumentMatchers.eq("walletSiteLabel"),
        org.mockito.ArgumentMatchers.eq("Realm Relying Party"));
    org.mockito.Mockito.verify(form).setAttribute(org.mockito.ArgumentMatchers.eq("walletChallengeLocator"),
        locator.capture());
    assertTrue(locator.getValue().startsWith(
        "https://idp.example:18886/auth/realms/demo/decent-wallet-login/v1/transactions/"));
  }



  @Test
  void authenticateStartsSignupTransactionFromBoundAuthenticationSessionIntent() {
    var transactionStore = mock(WalletLoginTransactionStore.class);
    var authenticator = new WalletChallengeAuthenticator(() -> transactionStore);
    var context = mock(AuthenticationFlowContext.class);
    var authSession = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
    var session = mock(org.keycloak.models.KeycloakSession.class);
    var keycloakContext = mock(org.keycloak.models.KeycloakContext.class);
    var uriInfo = mock(org.keycloak.models.KeycloakUriInfo.class);
    var rootSession = mock(org.keycloak.sessions.RootAuthenticationSessionModel.class);
    var client = mock(org.keycloak.models.ClientModel.class);
    var realm = mock(org.keycloak.models.RealmModel.class);
    var form = mock(org.keycloak.forms.login.LoginFormsProvider.class);
    var response = mock(jakarta.ws.rs.core.Response.class);
    var request = mock(org.keycloak.http.HttpRequest.class);
    var signupParameters = new jakarta.ws.rs.core.MultivaluedHashMap<String, String>();
    signupParameters.add("wallet_intent", "signup");
    when(context.getSession()).thenReturn(session);
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getHttpRequest()).thenReturn(request);
    when(request.getHttpMethod()).thenReturn("POST");
    when(request.getDecodedFormParameters()).thenReturn(signupParameters);
    when(authSession.getClientNote("decent.wallet.intent")).thenReturn("signup", "signup", null);
    when(context.getRealm()).thenReturn(realm);
    when(realm.isRegistrationAllowed()).thenReturn(true);
    when(context.form()).thenReturn(form);
    when(session.getContext()).thenReturn(keycloakContext);
    when(keycloakContext.getUri()).thenReturn(uriInfo);
    when(uriInfo.getBaseUri()).thenReturn(URI.create("https://idp.example:18886/auth/"));
    when(realm.getId()).thenReturn("realm-id");
    when(realm.getName()).thenReturn("demo");
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_SITE_LABEL)).thenReturn("Wallet Site");
    when(authSession.getClient()).thenReturn(client);
    when(authSession.getParentSession()).thenReturn(rootSession);
    when(rootSession.getId()).thenReturn("root-session-id");
    when(authSession.getTabId()).thenReturn("tab-id");
    when(client.getClientId()).thenReturn("client-public");
    when(client.getId()).thenReturn("client-id");
    when(client.isEnabled()).thenReturn(true);
    when(client.isStandardFlowEnabled()).thenReturn(true);
    when(client.getRedirectUris()).thenReturn(Set.of("https://site.example/callback"));
    when(authSession.getRedirectUri()).thenReturn("https://site.example/callback");
    var config = mock(org.keycloak.models.AuthenticatorConfigModel.class);
    when(context.getAuthenticatorConfig()).thenReturn(config);
    when(config.getConfig()).thenReturn(Map.of("trusted-origins", "https://idp.example:18886"));
    when(context.getActionUrl("signup-code")).thenReturn(URI.create("https://idp.example:18886/auth/action"));
    when(context.generateAccessCode()).thenReturn("signup-code");
    var execution = mock(org.keycloak.models.AuthenticationExecutionModel.class);
    when(context.getExecution()).thenReturn(execution);
    when(execution.getId()).thenReturn("execution-id");
    var issued = new WalletLoginTransactionStore.IssuedTransaction("A".repeat(43), "B".repeat(43),
        "C".repeat(43), Instant.now().plusSeconds(300));
    when(transactionStore.issue(org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(WalletLoginTransactionStore.Intent.SIGNUP))).thenReturn(issued);
    when(form.setAuthenticationSession(authSession)).thenReturn(form);
    when(form.setClientSessionCode(org.mockito.ArgumentMatchers.anyString())).thenReturn(form);
    when(form.setExecution(org.mockito.ArgumentMatchers.anyString())).thenReturn(form);
    when(form.setAuthContext(context)).thenReturn(form);
    when(form.setActionUri(org.mockito.ArgumentMatchers.any(URI.class))).thenReturn(form);
    when(form.setResponseHeader(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString())).thenReturn(form);
    when(form.setAttribute(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(form);
    when(form.createForm("wallet-login.ftl")).thenReturn(response);
    authenticator.authenticate(context);
    verify(transactionStore).issue(org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.eq(WalletLoginTransactionStore.Intent.SIGNUP));
    verify(authSession).removeClientNote("decent.wallet.intent");
    verify(context).challenge(response);
  }

  @Test
  void rejectsAuthenticatorWithoutTrustedOriginOrSiteLabelBeforeIssuingState() {
    var store = mock(WalletLoginTransactionStore.class);
    var authenticator = new WalletChallengeAuthenticator(() -> store);
    var context = mock(AuthenticationFlowContext.class);
    var auth = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
    var client = mock(org.keycloak.models.ClientModel.class);
    when(context.getAuthenticationSession()).thenReturn(auth);
    when(context.getHttpRequest()).thenReturn(mock(org.keycloak.http.HttpRequest.class));
    when(context.getRealm()).thenReturn(mock(org.keycloak.models.RealmModel.class));
    when(auth.getClient()).thenReturn(client);
    when(client.isEnabled()).thenReturn(true);
    when(client.isStandardFlowEnabled()).thenReturn(true);
    when(auth.getRedirectUri()).thenReturn("https://site.example/callback");
    when(client.getRedirectUris()).thenReturn(Set.of("https://site.example/callback"));
    when(context.getAuthenticatorConfig()).thenReturn(mock(org.keycloak.models.AuthenticatorConfigModel.class));
    when(context.getAuthenticatorConfig().getConfig()).thenReturn(Map.of("trusted-origins", "https://idp.example:18886",
        "site-name", "Ignored flow-local label"));
    when(context.getSession()).thenReturn(mock(org.keycloak.models.KeycloakSession.class));
    var session = context.getSession();
    var keycloakContext = mock(org.keycloak.models.KeycloakContext.class);
    var uri = mock(org.keycloak.models.KeycloakUriInfo.class);
    when(session.getContext()).thenReturn(keycloakContext);
    when(keycloakContext.getUri()).thenReturn(uri);
    when(uri.getBaseUri()).thenReturn(URI.create("https://idp.example:18886/auth/"));

    authenticator.authenticate(context);

    verify(context).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
    verify(store, org.mockito.Mockito.never()).issue(org.mockito.ArgumentMatchers.any());
  }

  @Test
  void signupChoiceIsBoundToCurrentAuthenticationSessionAndRestartsTheFlow() {
    var transactionStore = mock(WalletLoginTransactionStore.class);
    var authenticator = new WalletChallengeAuthenticator(() -> transactionStore);
    var context = mock(AuthenticationFlowContext.class);
    var authSession = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
    var request = mock(org.keycloak.http.HttpRequest.class);
    var parameters = new jakarta.ws.rs.core.MultivaluedHashMap<String, String>();
    parameters.add("wallet_intent", "signup");
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getHttpRequest()).thenReturn(request);
    when(request.getHttpMethod()).thenReturn("POST");
    when(request.getDecodedFormParameters()).thenReturn(parameters);
    authenticator.action(context);
    verify(authSession).setClientNote("decent.wallet.intent", "signup");
    verify(context).resetFlow(org.mockito.ArgumentMatchers.any(Runnable.class));
    verify(transactionStore, org.mockito.Mockito.never()).issue(
        org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
  }

  @Test
  void rejectsRepeatedOrUnsupportedSignupIntentParameters() {
    for (var values : java.util.List.of(
        java.util.List.of("signup", "login"), java.util.List.of("login"), java.util.List.of(""))) {
      var authenticator = new WalletChallengeAuthenticator(() -> mock(WalletLoginTransactionStore.class));
      var context = mock(AuthenticationFlowContext.class);
      var authSession = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
      var request = mock(org.keycloak.http.HttpRequest.class);
      var parameters = new jakarta.ws.rs.core.MultivaluedHashMap<String, String>();
      parameters.put("wallet_intent", new java.util.ArrayList<>(values));
      when(context.getAuthenticationSession()).thenReturn(authSession);
      when(context.getHttpRequest()).thenReturn(request);
      when(request.getHttpMethod()).thenReturn("POST");
      when(request.getDecodedFormParameters()).thenReturn(parameters);

      authenticator.action(context);

      verify(context).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
      verify(context, org.mockito.Mockito.never()).resetFlow();
      verify(authSession, org.mockito.Mockito.never()).setClientNote("decent.wallet.intent", "signup");
    }
  }

  @Test
  void authenticateRejectsClientsWithMultipleRedirectUrisBeforeIssuingState() {
    var store = mock(WalletLoginTransactionStore.class);
    var authenticator = new WalletChallengeAuthenticator(() -> store);
    var context = mock(AuthenticationFlowContext.class);
    var auth = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
    var client = mock(org.keycloak.models.ClientModel.class);
    when(context.getAuthenticationSession()).thenReturn(auth);
    when(context.getHttpRequest()).thenReturn(mock(org.keycloak.http.HttpRequest.class));
    when(context.getRealm()).thenReturn(mock(org.keycloak.models.RealmModel.class));
    when(auth.getClient()).thenReturn(client);
    when(client.isEnabled()).thenReturn(true);
    when(client.isStandardFlowEnabled()).thenReturn(true);
    when(auth.getRedirectUri()).thenReturn("https://site.example/callback");
    when(client.getRedirectUris()).thenReturn(Set.of(
        "https://site.example/callback", "https://other.example/callback"));

    authenticator.authenticate(context);

    verify(context).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
    verify(context, org.mockito.Mockito.never()).getSession();
    verify(store, org.mockito.Mockito.never()).issue(org.mockito.ArgumentMatchers.any());
  }

  @Test
  void defaultPortVariantsKeepTheResourceOriginSpelling() throws Exception {
    var method = WalletChallengeAuthenticator.class.getDeclaredMethod("canonicalOrigin", URI.class, String.class);
    method.setAccessible(true);
    for (var pair : java.util.List.of(
        new String[] {"https://idp.example/auth/", "https://idp.example:443"},
        new String[] {"https://idp.example:443/auth/", "https://idp.example"})) {
      URI base = URI.create(pair[0]);
      assertEquals(WalletLoginTransportResourceFactory.canonicalIdpOrigin(base, null),
          method.invoke(null, base, pair[1]));
    }
  }

  @Test
  void redirectPolicyRequiresOneExactHttpsUri() {
    assertEquals(true, WalletChallengeAuthenticator.isSingleExactHttpsRedirect(
        Set.of("https://site.example/callback"), "https://site.example/callback"));
    assertEquals(false, WalletChallengeAuthenticator.isSingleExactHttpsRedirect(
        Set.of("https://site.example/callback", "https://other.example/callback"),
        "https://site.example/callback"));
    assertEquals(false, WalletChallengeAuthenticator.isSingleExactHttpsRedirect(
        Set.of("http://site.example/callback"), "http://site.example/callback"));
    assertEquals(false, WalletChallengeAuthenticator.isSingleExactHttpsRedirect(
        Set.of("https://site.example/*"), "https://site.example/*"));
  }

  @Test
  void authenticateFailsClosedUntilVerifierIsImplemented() {
    var authenticator = new WalletChallengeAuthenticator();
    var context = mock(AuthenticationFlowContext.class);

    authenticator.authenticate(context);

    verify(context).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
  }

  @Test
  void callbackActionFailsClosedUntilVerifierIsImplemented() {
    var authenticator = new WalletChallengeAuthenticator();
    var context = mock(AuthenticationFlowContext.class);

    authenticator.action(context);

    verify(context).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
  }

  @Test
  void signupCallbackFailsClosedInsteadOfProvisioningAfterPendingProofWasConsumed() {
    String handle = "A".repeat(43);
    String identityId = "mailto:signup@example.org";
    var binding = new WalletLoginTransactionStore.Binding("realm-id", "client-id", "root-session-id",
        "tab-id", "https://site.example/callback", "https://idp.example");
    var accepted = new WalletLoginTransactionStore.AcceptedTransaction(identityId, "AA", "digest", binding,
        WalletLoginTransactionStore.Intent.SIGNUP);
    var store = mock(WalletLoginTransactionStore.class);
    when(store.getAccepted(handle, binding)).thenReturn(java.util.Optional.of(accepted));
    var authenticator = new WalletChallengeAuthenticator(() -> store);
    var context = mock(AuthenticationFlowContext.class);
    var session = mock(org.keycloak.models.KeycloakSession.class);
    var realm = mock(org.keycloak.models.RealmModel.class);
    var auth = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
    var root = mock(org.keycloak.sessions.RootAuthenticationSessionModel.class);
    var client = mock(org.keycloak.models.ClientModel.class);
    var users = mock(org.keycloak.models.UserProvider.class);
    var lateUser = mock(org.keycloak.models.UserModel.class);
    when(context.getAuthenticationSession()).thenReturn(auth);
    when(context.getRealm()).thenReturn(realm);
    when(realm.getId()).thenReturn("realm-id");
    when(realm.isRegistrationAllowed()).thenReturn(true);
    when(context.getSession()).thenReturn(session);
    when(auth.getClient()).thenReturn(client);
    when(auth.getParentSession()).thenReturn(root);
    when(auth.getTabId()).thenReturn("tab-id");
    when(auth.getRedirectUri()).thenReturn("https://site.example/callback");
    when(auth.getAuthNote("decent.wallet.handle")).thenReturn(handle);
    when(auth.getAuthNote("decent.wallet.origin")).thenReturn("https://idp.example");
    when(client.getId()).thenReturn("client-id");
    when(root.getId()).thenReturn("root-session-id");
    when(session.users()).thenReturn(users);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(java.util.stream.Stream.empty());
    when(users.addUser(realm, null, "late-signup-user", true, true)).thenReturn(lateUser);

    authenticator.action(context);

    verify(users, org.mockito.Mockito.never()).addUser(
        org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
        org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyBoolean(),
        org.mockito.ArgumentMatchers.anyBoolean());
    verify(store).getAccepted(handle, binding);
    verify(store, org.mockito.Mockito.never()).takeAccepted(handle, binding);
    verify(context).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
    verify(context, org.mockito.Mockito.never()).success();
  }

  @Test
  void callbackDoesNotConsumeGateWhenLocalUserMappingIsMissing() {
    String handle = "A".repeat(43);
    String identityId = "mailto:alice@example.org";
    var binding = new WalletLoginTransactionStore.Binding("realm-id", "client-id", "root-session-id",
        "tab-id", "https://site.example/callback", "https://idp.example");
    var accepted = new WalletLoginTransactionStore.AcceptedTransaction(identityId, "AA", "digest", binding);
    var store = mock(WalletLoginTransactionStore.class);
    when(store.getAccepted(handle, binding)).thenReturn(java.util.Optional.of(accepted));
    var authenticator = new WalletChallengeAuthenticator(() -> store);
    var context = mock(AuthenticationFlowContext.class);
    var session = mock(org.keycloak.models.KeycloakSession.class);
    var realm = mock(org.keycloak.models.RealmModel.class);
    var auth = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
    var root = mock(org.keycloak.sessions.RootAuthenticationSessionModel.class);
    var client = mock(org.keycloak.models.ClientModel.class);
    var users = mock(org.keycloak.models.UserProvider.class);
    when(context.getAuthenticationSession()).thenReturn(auth);
    when(context.getRealm()).thenReturn(realm);
    when(realm.getId()).thenReturn("realm-id");
    when(context.getSession()).thenReturn(session);
    when(auth.getClient()).thenReturn(client);
    when(auth.getParentSession()).thenReturn(root);
    when(auth.getTabId()).thenReturn("tab-id");
    when(auth.getRedirectUri()).thenReturn("https://site.example/callback");
    when(auth.getAuthNote("decent.wallet.handle")).thenReturn(handle);
    when(auth.getAuthNote("decent.wallet.origin")).thenReturn("https://idp.example");
    when(client.getId()).thenReturn("client-id");
    when(root.getId()).thenReturn("root-session-id");
    when(session.users()).thenReturn(users);
    when(users.searchForUserByUserAttributeStream(realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(java.util.stream.Stream.empty());

    authenticator.action(context);

    verify(store).getAccepted(handle, binding);
    verify(store, org.mockito.Mockito.never()).takeAccepted(handle, binding);
    verify(context).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
  }

  @Test
  void providerHasNoUserSetupFallback() {
    var authenticator = new WalletChallengeAuthenticator();

    assertEquals(false, authenticator.requiresUser());
    assertEquals(false, authenticator.configuredFor(null, null, null));
  }
}
