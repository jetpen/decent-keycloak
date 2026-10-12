package org.decentwallet.keycloak.wallet;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

final class WalletChallengeAuthenticatorTest {
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
    org.mockito.Mockito.when(context.getRealm()).thenReturn(realm);
    org.mockito.Mockito.when(context.form()).thenReturn(form);
    org.mockito.Mockito.when(session.getContext()).thenReturn(keycloakContext);
    org.mockito.Mockito.when(session.singleUseObjects()).thenReturn(mock(org.keycloak.models.SingleUseObjectProvider.class));
    org.mockito.Mockito.when(keycloakContext.getUri()).thenReturn(uriInfo);
    org.mockito.Mockito.when(uriInfo.getBaseUri()).thenReturn(URI.create("https://idp.example/auth/"));
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
    Map<String, String> configured = Map.of("trusted-origins", "https://idp.example");
    var authenticatorConfig = mock(org.keycloak.models.AuthenticatorConfigModel.class);
    org.mockito.Mockito.when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
    org.mockito.Mockito.when(authenticatorConfig.getConfig()).thenReturn(configured);
    org.mockito.Mockito.when(context.getRefreshExecutionUrl()).thenReturn(URI.create("https://idp.example/refresh?code=abc&execution=exec&client_id=client&tab_id=tab"));
    org.mockito.Mockito.when(context.generateAccessCode()).thenReturn("access-code");
    var execution = mock(org.keycloak.models.AuthenticationExecutionModel.class);
    org.mockito.Mockito.when(context.getExecution()).thenReturn(execution);
    org.mockito.Mockito.when(execution.getId()).thenReturn("execution-id");
    var issued = new WalletLoginTransactionStore.IssuedTransaction("A".repeat(43), "B".repeat(43), "C".repeat(43), Instant.now().plusSeconds(300));
    org.mockito.Mockito.when(transactionStore.issue(org.mockito.ArgumentMatchers.any())).thenReturn(issued);
    org.mockito.Mockito.when(form.setAuthenticationSession(authSession)).thenReturn(form);
    org.mockito.Mockito.when(form.setClientSessionCode(org.mockito.ArgumentMatchers.anyString())).thenReturn(form);
    org.mockito.Mockito.when(form.setExecution(org.mockito.ArgumentMatchers.anyString())).thenReturn(form);
    org.mockito.Mockito.when(form.setAuthContext(context)).thenReturn(form);
    org.mockito.Mockito.when(form.setActionUri(org.mockito.ArgumentMatchers.any(URI.class))).thenReturn(form);
    org.mockito.Mockito.when(form.setResponseHeader(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString())).thenReturn(form);
    org.mockito.Mockito.when(form.setAttribute(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any())).thenReturn(form);
    org.mockito.Mockito.when(form.createForm("wallet-login.ftl")).thenReturn(response);

    authenticator.authenticate(context);

    org.mockito.Mockito.verify(transactionStore).issue(org.mockito.ArgumentMatchers.any());
    org.mockito.Mockito.verify(context).challenge(response);
    org.mockito.Mockito.verify(form).setResponseHeader("Cache-Control", "no-store");
    org.mockito.Mockito.verify(form).setResponseHeader("Referrer-Policy", "no-referrer");
    var locator = org.mockito.ArgumentCaptor.forClass(String.class);
    org.mockito.Mockito.verify(form).setAttribute(org.mockito.ArgumentMatchers.eq("walletChallengeLocator"),
        locator.capture());
    assertEquals(true, locator.getValue().startsWith(
        "https://idp.example/auth/realms/demo/decent-wallet-login/v1/transactions/"));
  }

  @Test
  void authenticateRejectsClientsWithMultipleRedirectUrisBeforeIssuingState() {
    var store = mock(WalletLoginTransactionStore.class);
    var authenticator = new WalletChallengeAuthenticator(() -> store);
    var context = mock(AuthenticationFlowContext.class);
    var auth = mock(org.keycloak.sessions.AuthenticationSessionModel.class);
    var client = mock(org.keycloak.models.ClientModel.class);
    when(context.getAuthenticationSession()).thenReturn(auth);
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
