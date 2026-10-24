package org.decentwallet.keycloak.wallet;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowCallbackFactory;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.AuthenticatorUtil;
import org.keycloak.authentication.DefaultAuthenticationFlow;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.http.HttpRequest;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.ExecutionStatus;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class WalletCallbackReplayFlowTest {
  private static final String EXECUTION_ID = "wallet-execution";
  private static final String FLOW_ID = "browser-flow";

  @Test
  void completedWalletExecutionIsRearmedBeforeAStaleCallbackReentersTheFlow() {
    var authSession = mock(AuthenticationSessionModel.class);
    var rootSession = mock(RootAuthenticationSessionModel.class);
    when(authSession.getParentSession()).thenReturn(rootSession);
    var executionStatuses = new HashMap<String, ExecutionStatus>();
    executionStatuses.put(EXECUTION_ID, ExecutionStatus.SUCCESS);
    var clientNotes = new HashMap<String, String>();
    clientNotes.put("decent.wallet.callback.completed", "true");
    clientNotes.put("decent.wallet.callback.execution", EXECUTION_ID);
    clientNotes.put("decent.wallet.callback.request", "a".repeat(32));
    var authNotes = new HashMap<String, String>();
    authNotes.put(AuthenticatorUtil.CALLBACKS_FACTORY_IDS_NOTE,
        WalletChallengeAuthenticatorFactory.ID);
    when(authSession.getExecutionStatus()).thenReturn(executionStatuses);
    when(authSession.getAuthNote(anyString()))
        .thenAnswer(invocation -> authNotes.get(invocation.getArgument(0, String.class)));
    doAnswer(invocation -> {
      authNotes.put(invocation.getArgument(0), invocation.getArgument(1));
      return null;
    }).when(authSession).setAuthNote(anyString(), anyString());
    doAnswer(invocation -> {
      authNotes.clear();
      return null;
    }).when(authSession).clearAuthNotes();
    doAnswer(invocation -> {
      executionStatuses.clear();
      return null;
    }).when(authSession).clearExecutionStatus();
    when(authSession.getClientNote(anyString()))
        .thenAnswer(invocation -> clientNotes.get(invocation.getArgument(0, String.class)));
    doAnswer(invocation -> {
      clientNotes.put(invocation.getArgument(0), invocation.getArgument(1));
      return null;
    }).when(authSession).setClientNote(anyString(), anyString());
    doAnswer(invocation -> {
      executionStatuses.put(invocation.getArgument(0), invocation.getArgument(1));
      return null;
    }).when(authSession).setExecutionStatus(anyString(), any(ExecutionStatus.class));

    var keycloakContext = mock(KeycloakContext.class);
    when(keycloakContext.getAuthenticationSession()).thenReturn(authSession);
    var session = mock(KeycloakSession.class);
    when(session.getContext()).thenReturn(keycloakContext);

    var execution = mock(AuthenticationExecutionModel.class);
    when(execution.getId()).thenReturn(EXECUTION_ID);
    when(execution.getAuthenticator()).thenReturn(WalletChallengeAuthenticatorFactory.ID);
    when(execution.isDisabled()).thenReturn(false);
    when(execution.isRequired()).thenReturn(true);
    when(execution.isConditional()).thenReturn(false);
    when(execution.isAuthenticatorFlow()).thenReturn(false);

    var realm = mock(RealmModel.class);
    when(realm.getAuthenticationExecutionsStream(FLOW_ID)).thenAnswer(invocation -> Stream.of(execution));
    var flowModel = mock(AuthenticationFlowModel.class);
    when(flowModel.getId()).thenReturn(FLOW_ID);
    when(flowModel.getAlias()).thenReturn(FLOW_ID);
    when(flowModel.isTopLevel()).thenReturn(true);

    var factory = new WalletChallengeAuthenticatorFactory();
    assertInstanceOf(AuthenticationFlowCallbackFactory.class, factory);
    var sessionFactory = mock(KeycloakSessionFactory.class);
    when(sessionFactory.getProviderFactory(Authenticator.class, WalletChallengeAuthenticatorFactory.ID))
        .thenReturn(factory);
    when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
    when(session.getProvider(Authenticator.class, WalletChallengeAuthenticatorFactory.ID))
        .thenReturn(factory.create(session));

    var processor = mock(AuthenticationProcessor.class);
    when(processor.getRealm()).thenReturn(realm);
    when(processor.getAuthenticationSession()).thenReturn(authSession);
    when(processor.getSession()).thenReturn(session);
    when(processor.isSuccessful(execution)).thenReturn(true);

    var flow = new DefaultAuthenticationFlow(processor, flowModel);
    assertNull(flow.processFlow());
    assertTrue(flow.isSuccessful());

    assertEquals(ExecutionStatus.CHALLENGED, executionStatuses.get(EXECUTION_ID));
    AuthenticationProcessor.resetFlow(authSession, FLOW_ID);
    assertEquals("true", clientNotes.get("decent.wallet.callback.completed"));

    when(authSession.getProtocol()).thenReturn("openid-connect");
    var client = mock(org.keycloak.models.ClientModel.class);
    when(realm.getName()).thenReturn("test-realm");
    when(client.getRedirectUris()).thenReturn(Set.of("https://rp.example/callback?tenant=one"));
    when(authSession.getClient()).thenReturn(client);
    when(authSession.getRedirectUri()).thenReturn("https://rp.example/callback?tenant=one");
    when(authSession.getTabId()).thenReturn("wallet-tab");
    when(authSession.getClientNote("response_type")).thenReturn("code");
    when(authSession.getClientNote("state")).thenReturn("original-state");
    when(rootSession.getAuthenticationSessions()).thenReturn(
        Map.of("another-tab", mock(AuthenticationSessionModel.class)));
    when(keycloakContext.getClient()).thenReturn(client);
    var keycloakUri = mock(org.keycloak.models.KeycloakUriInfo.class);
    when(keycloakContext.getUri()).thenReturn(keycloakUri);
    when(keycloakUri.getBaseUri()).thenReturn(URI.create("https://idp.example:18886/auth/"));
    var requestHeaders = mock(HttpHeaders.class);
    var request = mock(HttpRequest.class);
    when(request.getHttpHeaders()).thenReturn(requestHeaders);
    var uriInfo = mock(UriInfo.class);
    var event = mock(EventBuilder.class);
    var protocol = new OIDCLoginProtocol(session, realm, uriInfo, requestHeaders, event);
    when(session.getProvider(LoginProtocol.class, "openid-connect")).thenReturn(protocol);

    var replayContext = mock(AuthenticationProcessor.Result.class);
    when(replayContext.getExecution()).thenReturn(execution);
    when(replayContext.getAuthenticationSession()).thenReturn(authSession);
    when(replayContext.getEvent()).thenReturn(event);
    when(replayContext.getSession()).thenReturn(session);
    when(replayContext.getRealm()).thenReturn(realm);
    when(replayContext.getHttpRequest()).thenReturn(request);
    when(replayContext.getUriInfo()).thenReturn(uriInfo);
    when(replayContext.getStatus()).thenReturn(FlowStatus.FORCE_CHALLENGE);
    var replayResponse = new java.util.concurrent.atomic.AtomicReference<Response>();
    doAnswer(invocation -> {
      replayResponse.set(invocation.getArgument(0, Response.class));
      return null;
    }).when(replayContext).forceChallenge(any(Response.class));
    when(replayContext.getChallenge()).thenAnswer(invocation -> replayResponse.get());
    when(processor.createAuthenticatorContext(eq(execution), any(Authenticator.class), anyList()))
        .thenReturn(replayContext);

    var replayFlow = new DefaultAuthenticationFlow(processor, flowModel);
    Response response = replayFlow.processFlow();
    assertEquals(replayResponse.get(), response);
    assertNotNull(response);
    assertTrue(response.getStatus() == 302 || response.getStatus() == 303);
    URI location = URI.create(response.getHeaderString("Location"));
    assertEquals("https", location.getScheme());
    assertEquals("rp.example", location.getHost());
    assertEquals("/callback", location.getPath());
    var query = new HashMap<String, java.util.List<String>>();
    for (String component : java.net.URLDecoder.decode(location.getRawQuery(),
        java.nio.charset.StandardCharsets.UTF_8).split("&")) {
      String[] pair = component.split("=", 2);
      query.computeIfAbsent(pair[0], ignored -> new java.util.ArrayList<>())
          .add(pair.length == 2 ? pair[1] : "");
    }
    assertEquals(List.of("one"), query.get("tenant"));
    assertEquals(List.of("original-state"), query.get("state"));
    assertEquals(List.of("access_denied"), query.get("error"));
    assertFalse(query.containsKey("code"));
  }
}
