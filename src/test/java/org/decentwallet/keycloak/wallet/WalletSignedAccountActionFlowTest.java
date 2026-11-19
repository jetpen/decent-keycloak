package org.decentwallet.keycloak.wallet;

import static org.decentwallet.keycloak.wallet.WalletLoginTransactionStore.Intent.ACCOUNT_SIGNUP;
import static org.decentwallet.keycloak.wallet.WalletLoginTransactionStore.Intent.SIGNUP_RECOVERY;
import static org.decentwallet.keycloak.wallet.WalletLoginTransportHandlerTest.configureSignedRequestParser;
import static org.decentwallet.keycloak.wallet.WalletLoginTransportHandlerTest.parseAuthorizationRequest;
import static org.decentwallet.keycloak.wallet.WalletLoginTransportHandlerTest.rawKey;
import static org.decentwallet.keycloak.wallet.WalletLoginTransportHandlerTest.signedProof;
import static org.decentwallet.keycloak.wallet.WalletLoginTransportHandlerTest.signedRequestObject;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.protocol.oidc.utils.OIDCResponseType;
import org.keycloak.services.clientpolicy.context.AuthorizationRequestContext;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/** Exercises the provider through authenticator success, not OIDC code issuance or HTTP dispatch. */
final class WalletSignedAccountActionFlowTest {
  private static final String ORIGIN = "https://idp.example";
  private static final String REDIRECT = "https://site.example/callback";
  private static final String CLIENT = "rp-client";
  private static final String IDENTITY = "mailto:account-flow@example.test";
  private static final String IDENTITY_ATTRIBUTE = "decent_identity_id";
  private static final String HANDLE_NOTE = "decent.wallet.handle";
  private static final String COMPLETE_NOTE = "decent.wallet.callback.completed";
  private static final String RP_KID = "registered-rp-key";
  private static final SecureRandom RANDOM = new SecureRandom();

  @Test
  void signedSignupCreatesOneEnabledPrincipalAndResumesItsOriginalSession() throws Exception {
    var fixture = new ProviderFixture();
    assertTrue(fixture.accounts.isEmpty());
    var signup = fixture.start("signup", ACCOUNT_SIGNUP);

    try (var response = fixture.submit(signup)) {
      assertEquals(202, response.getStatus());
      assertEquals(Map.of("status", "pending"), response.getEntity());
      assertNull(response.getLocation());
    }
    assertEquals(List.of("registry", "lookup"), fixture.accountEvents.subList(0, 2));
    var created = fixture.accounts.values().stream().toList();
    assertEquals(1, created.size());
    assertTrue(created.getFirst().isEnabled());
    assertEquals(IDENTITY, created.getFirst().getFirstAttribute(IDENTITY_ATTRIBUTE));
    fixture.assertAccepted(signup);
    fixture.resume(signup, created.getFirst());
    assertEquals(created, fixture.accounts.values().stream().toList());
    verify(fixture.users).addUser(eq(fixture.realm), isNull(), anyString(), eq(true), eq(true));
  }

  @Test
  void signedSignupDeniesAnEnabledExactPrincipalButFreshRecoveryResumesOnlyItsOwnSession()
      throws Exception {
    var fixture = new ProviderFixture();
    var existing = fixture.existingAccount();
    var signup = fixture.start("signup", ACCOUNT_SIGNUP);
    fixture.assertDeniedAndPending(signup, 403);
    assertEquals(List.of("registry", "lookup"), fixture.accountEvents,
        "ordinary signup must reach the exact account lookup after production proof verification");
    verify(existing).isEnabled();
    assertNoAccountWrites(fixture, existing);
    assertTrue(fixture.singleUse.storedKeys().stream().noneMatch(key ->
        key.startsWith("decent-wallet-login-v1:accepted:") || key.startsWith("decent-wallet-login-v1:callback:")));

    fixture.accountEvents.clear();
    var recovery = fixture.start("signup_recovery", SIGNUP_RECOVERY);
    assertNotEquals(signup.request().state(), recovery.request().state());
    assertNotEquals(signup.request().nonce(), recovery.request().nonce());
    assertNotEquals(signup.request().verifier(), recovery.request().verifier());
    assertNotEquals(signup.request().challenge(), recovery.request().challenge());
    assertNotEquals(signup.request().jti(), recovery.request().jti());
    assertNotEquals(signup.request().id(), recovery.request().id());
    assertNotEquals(signup.binding(), recovery.binding());
    assertNotEquals(signup.handle(), recovery.handle());
    assertNotEquals(signup.pending().challenge(), recovery.pending().challenge());
    assertFalse(MessageDigest.isEqual(signup.proof(), recovery.proof()));

    try (var response = fixture.submit(recovery)) {
      assertEquals(202, response.getStatus());
      assertEquals(Map.of("status", "pending"), response.getEntity());
      assertNull(response.getLocation());
    }
    assertEquals(List.of("registry", "lookup"), fixture.accountEvents);
    fixture.assertAccepted(recovery);
    try (var wrongBrowser = fixture.status(signup, recovery.handle(), recovery.pending().csrfToken())) {
      assertEmpty(wrongBrowser, 404);
    }
    // Re-enter the original denied action while the separate recovery gate is live.
    fixture.authenticator.action(signup.flow());
    verify(signup.flow(), times(2)).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
    fixture.resume(recovery, existing);
    fixture.assertPending(signup);
    verify(signup.auth(), never()).setAuthenticatedUser(any());
    verify(signup.flow(), never()).success();
    assertEquals(Map.of("existing-subject", existing), fixture.accounts);
    assertNoAccountWrites(fixture, existing);
  }

  @Test
  void signedSignupWithUnavailableExactLookupStaysPendingWithoutCreatingAnAccount() throws Exception {
    var fixture = new ProviderFixture();
    fixture.lookupUnavailable = true;
    var signup = fixture.start("signup", ACCOUNT_SIGNUP);
    fixture.assertDeniedAndPending(signup, 503);
    assertEquals(List.of("registry", "lookup"), fixture.accountEvents);
    assertTrue(fixture.accounts.isEmpty());
    verify(fixture.users, never()).addUser(any(), any(), anyString(), anyBoolean(), anyBoolean());
  }

  private static void assertNoAccountWrites(ProviderFixture fixture, UserModel existing) {
    verify(fixture.users, never()).addUser(any(), any(), anyString(), anyBoolean(), anyBoolean());
    verify(fixture.users, never()).addUser(any(), anyString());
    verify(fixture.users, never()).removeUser(any(), any());
    // Existing-account fixture only stubs reads; an unexpected mutation is an unverified interaction.
    verifyNoMoreInteractions(ignoreStubs(existing));
  }

  private static void assertEmpty(Response response, int status) {
    assertEquals(status, response.getStatus());
    assertFalse(response.hasEntity());
    assertNull(response.getLocation());
    assertFalse(response.getHeaders().containsKey("Location"));
  }

  private static byte[] sha256(byte[] bytes) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(bytes);
  }

  private static String base64(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static String randomToken(int size) {
    var bytes = new byte[size];
    RANDOM.nextBytes(bytes);
    return base64(bytes);
  }

  private record Request(String state, String nonce, String verifier, String challenge,
      String id, String jti) {
    static Request fresh() throws Exception {
      var verifier = randomToken(32);
      return new Request(randomToken(16), randomToken(16), verifier,
          base64(sha256(verifier.getBytes(StandardCharsets.US_ASCII))), randomToken(16), randomToken(16));
    }
  }

  private record Ceremony(Request request, AuthenticationSessionModel auth, AuthenticationFlowContext flow,
      String handle, WalletLoginTransactionStore.PendingTransaction pending, URI actionUrl, byte[] proof) {
    WalletLoginTransactionStore.Binding binding() { return pending.binding(); }
  }

  private static final class ProviderFixture {
    final KeycloakSession session = mock(KeycloakSession.class);
    final RealmModel realm = mock(RealmModel.class);
    final ClientModel client = mock(ClientModel.class);
    final KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
    final UserProvider users = mock(UserProvider.class);
    final Map<String, UserModel> accounts = new HashMap<>();
    final List<String> accountEvents = new ArrayList<>();
    final WalletLoginTransportHandlerTest.MemoryStore singleUse = new WalletLoginTransportHandlerTest.MemoryStore();
    final WalletLoginTransactionStore readback = new WalletLoginTransactionStore(singleUse, RANDOM, Clock.systemUTC());
    final WalletAccountRequestExecutor policy = new WalletAccountRequestExecutor(session);
    final WalletChallengeAuthenticator authenticator;
    final KeyPair ownerKey;
    final KeyPair rpKey;
    boolean lookupUnavailable;

    ProviderFixture() throws Exception {
      ownerKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      var ec = KeyPairGenerator.getInstance("EC");
      ec.initialize(new ECGenParameterSpec("secp256r1"));
      rpKey = ec.generateKeyPair();
      configureSignedRequestParser(session, rpKey);
      var context = mock(KeycloakContext.class);
      when(session.getContext()).thenReturn(context);
      when(session.singleUseObjects()).thenReturn(singleUse);
      when(session.users()).thenReturn(users);
      when(context.getRealm()).thenReturn(realm);
      when(context.getUri()).thenReturn(uriInfo);
      when(uriInfo.getBaseUri()).thenReturn(URI.create(ORIGIN + "/"));
      when(realm.getId()).thenReturn("realm-id");
      when(realm.getName()).thenReturn("demo");
      when(realm.isRegistrationAllowed()).thenReturn(true);
      when(realm.getClientByClientId(CLIENT)).thenReturn(client);
      when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_SITE_LABEL)).thenReturn("Example Site");
      when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_REGISTRY_BOOTSTRAP)).thenReturn("offline-peer");
      when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_REGISTRY_CLIENT_PORT)).thenReturn("12345");
      when(client.getClientId()).thenReturn(CLIENT);
      when(client.getId()).thenReturn("client-id");
      when(client.getRealm()).thenReturn(realm);
      when(client.isEnabled()).thenReturn(true);
      when(client.isStandardFlowEnabled()).thenReturn(true);
      when(client.getRedirectUris()).thenReturn(Set.of(REDIRECT));
      when(client.getAttribute(OIDCConfigAttributes.REQUEST_OBJECT_SIGNATURE_ALG)).thenReturn("ES256");
      when(client.getAttribute(OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED))
          .thenReturn(OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST);
      var config = new WalletAccountRequestExecutor.Configuration();
      config.setEnabled(true);
      policy.setupConfiguration(config);
      authenticator = (WalletChallengeAuthenticator) new WalletChallengeAuthenticatorFactory().create(session);

      when(users.searchForUserByUserAttributeStream(any(), anyString(), anyString())).thenAnswer(call -> {
        assertSame(realm, call.getArgument(0));
        assertEquals(IDENTITY_ATTRIBUTE, call.getArgument(1));
        assertEquals(IDENTITY, call.getArgument(2));
        accountEvents.add("lookup");
        return lookupUnavailable ? null : accounts.values().stream()
            .filter(user -> IDENTITY.equals(user.getFirstAttribute(IDENTITY_ATTRIBUTE)));
      });
      when(users.addUser(any(), any(), anyString(), anyBoolean(), anyBoolean())).thenAnswer(call -> {
        assertSame(realm, call.getArgument(0));
        accountEvents.add("create");
        String username = call.getArgument(2);
        var user = mock(UserModel.class);
        var attributes = new HashMap<String, String>();
        var enabled = new AtomicBoolean();
        when(user.getId()).thenReturn("provisioned-subject");
        when(user.getFirstAttribute(anyString())).thenAnswer(read -> attributes.get(read.getArgument(0)));
        when(user.isEnabled()).thenAnswer(read -> enabled.get());
        doAnswer(write -> { attributes.put(write.getArgument(0), write.getArgument(1)); return null; })
            .when(user).setSingleAttribute(anyString(), anyString());
        doAnswer(write -> { enabled.set(write.getArgument(0)); return null; }).when(user).setEnabled(anyBoolean());
        assertNull(accounts.putIfAbsent(username, user));
        return user;
      });
    }

    UserModel existingAccount() {
      var existing = mock(UserModel.class);
      when(existing.getId()).thenReturn("existing-subject");
      when(existing.getFirstAttribute(IDENTITY_ATTRIBUTE)).thenReturn(IDENTITY);
      when(existing.isEnabled()).thenReturn(true);
      accounts.put(existing.getId(), existing);
      return existing;
    }

    Ceremony start(String action, WalletLoginTransactionStore.Intent intent) throws Exception {
      var request = Request.fresh();
      var auth = newAuthenticationSession();
      long now = Instant.now().getEpochSecond();
      long expires = now + 240;
      var payload = new ObjectMapper().createObjectNode()
          .put("iss", CLIENT).put("client_id", CLIENT).put("aud", ORIGIN + "/realms/demo")
          .put("response_type", "code").put("response_mode", "query").put("redirect_uri", REDIRECT)
          .put("scope", "openid").put("state", request.state()).put("nonce", request.nonce())
          .put("code_challenge", request.challenge()).put("code_challenge_method", "S256")
          .put("iat", now).put("exp", expires).put("jti", request.jti())
          .put(WalletAccountRequestExecutor.ACTION_PARAM, action);
      var extension = payload.putObject(WalletAccountRequestExecutor.REQUEST_PARAM)
          .put("profile", "decent-account-disclosure-v1").put("request_id", request.id())
          .put("purpose", "Create an Example Site account (" + action + ")");
      extension.putArray("claims").addObject().put("id", "urn:decent:account:v1:email").put("required", false);
      var params = new MultivaluedHashMap<String, String>();
      params.add("client_id", CLIENT);
      params.add("request", signedRequestObject(payload, rpKey, RP_KID));
      var parsed = parseAuthorizationRequest(session, client, params);
      policy.executeOnEvent(new AuthorizationRequestContext(mock(OIDCResponseType.class), parsed,
          parsed.getRedirectUri(), params, auth));

      // Project the real parser result using the pinned endpoint's note conventions.
      // This fixture does not invoke AuthorizationEndpoint.buildGet or activate realm client policies.
      auth.setRedirectUri(parsed.getRedirectUri());
      AuthorizationEndpoint.performActionOnParameters(parsed, auth::setClientNote);
      parsed.getAdditionalReqParams().forEach((key, value) -> auth.setClientNote(
          AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + key, value));
      assertEquals("true", auth.getAuthNote(WalletAccountRequestExecutor.AUTH_NOTE_SIGNED));
      assertEquals(action, auth.getAuthNote(WalletAccountRequestExecutor.AUTH_NOTE_ACTION));
      assertEquals(request.state(), auth.getClientNote("state"));
      assertEquals(request.nonce(), auth.getClientNote("nonce"));
      assertEquals(request.challenge(), auth.getClientNote("code_challenge"));
      assertEquals("S256", auth.getClientNote("code_challenge_method"));
      assertEquals(REDIRECT, auth.getRedirectUri());

      var flow = mock(AuthenticationFlowContext.class);
      var form = mock(LoginFormsProvider.class, RETURNS_SELF);
      var execution = mock(AuthenticationExecutionModel.class);
      var config = mock(AuthenticatorConfigModel.class);
      when(flow.getSession()).thenReturn(session);
      when(flow.getRealm()).thenReturn(realm);
      when(flow.getAuthenticationSession()).thenReturn(auth);
      when(flow.getExecution()).thenReturn(execution);
      when(execution.getId()).thenReturn("wallet-execution");
      when(flow.form()).thenReturn(form);
      when(flow.getAuthenticatorConfig()).thenReturn(config);
      when(config.getConfig()).thenReturn(Map.of("trusted-origins", ORIGIN));
      // This is Keycloak's execution URL for the authenticator, not an OAuth authorization code.
      var actionUrl = URI.create(ORIGIN + "/login-actions/authenticate?tab_id=" + auth.getTabId());
      when(flow.generateAccessCode()).thenReturn("fixture-execution-access-code");
      when(flow.getActionUrl("fixture-execution-access-code")).thenReturn(actionUrl);
      try (var page = Response.ok().build()) {
        when(form.createForm("wallet-login.ftl")).thenReturn(page);
        authenticator.authenticate(flow);
        verify(flow).challenge(page);
      }
      verify(flow, never()).success();
      var handle = auth.getAuthNote(HANDLE_NOTE);
      assertNotNull(handle);
      var pending = readback.load(handle).orElseThrow();
      assertEquals(new WalletLoginTransactionStore.Binding("realm-id", "client-id", auth.getParentSession().getId(),
          auth.getTabId(), REDIRECT, ORIGIN), pending.binding());
      assertEquals(intent, pending.intent());
      assertEquals(action, pending.accountAction());
      assertEquals(request.id(), pending.accountRequestId());
      assertEquals(request.jti(), pending.accountRequestJti());
      assertEquals(Long.toString(expires), pending.accountRequestExpires());
      assertNotEquals(request.nonce(), pending.challenge());
      assertTrue(readback.getAccepted(handle, pending.binding()).isEmpty());
      return new Ceremony(request, auth, flow, handle, pending, actionUrl,
          signedProof(pending.challenge(), IDENTITY, ownerKey));
    }

    private AuthenticationSessionModel newAuthenticationSession() {
      var auth = mock(AuthenticationSessionModel.class);
      var root = mock(RootAuthenticationSessionModel.class);
      var authNotes = new HashMap<String, String>();
      var clientNotes = new HashMap<String, String>();
      var redirect = new AtomicReference<String>();
      when(root.getId()).thenReturn(randomToken(16));
      when(auth.getTabId()).thenReturn(randomToken(16));
      when(auth.getParentSession()).thenReturn(root);
      when(auth.getClient()).thenReturn(client);
      when(auth.getRedirectUri()).thenAnswer(call -> redirect.get());
      doAnswer(call -> { redirect.set(call.getArgument(0)); return null; }).when(auth).setRedirectUri(anyString());
      when(auth.getAuthNote(anyString())).thenAnswer(call -> authNotes.get(call.getArgument(0)));
      when(auth.getClientNote(anyString())).thenAnswer(call -> clientNotes.get(call.getArgument(0)));
      doAnswer(call -> { authNotes.put(call.getArgument(0), call.getArgument(1)); return null; })
          .when(auth).setAuthNote(anyString(), any());
      doAnswer(call -> { clientNotes.put(call.getArgument(0), call.getArgument(1)); return null; })
          .when(auth).setClientNote(anyString(), any());
      doAnswer(call -> { authNotes.remove(call.getArgument(0)); return null; }).when(auth).removeAuthNote(anyString());
      return auth;
    }

    Response submit(Ceremony ceremony) {
      // A native wallet request has no initiating-browser cookie or OIDC query parameters.
      when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
      try (var registry = mockConstruction(ProcessIdentityResolver.class, (resolver, ignored) -> {
        when(resolver.resolveExact(anyString())).thenAnswer(call -> {
          assertEquals(IDENTITY, call.getArgument(0));
          accountEvents.add("registry");
          return new WalletIdentityKeyResolver.ResolvedIdentityKey(IDENTITY, rawKey(ownerKey));
        });
      })) {
        return resource().transactionPost(ceremony.handle(), null, null, null, null,
            "application/json", null, new ByteArrayInputStream(ceremony.proof()));
      }
    }

    Response status(Ceremony browser, String handle, String csrf) {
      var params = new MultivaluedHashMap<String, String>();
      params.add("client_id", CLIENT);
      params.add("tab_id", browser.binding().tabId());
      when(uriInfo.getQueryParameters()).thenReturn(params);
      try (var registry = mockConstruction(ProcessIdentityResolver.class);
           var cookies = mockConstruction(AuthenticationSessionManager.class, (manager, ignored) ->
               when(manager.getCurrentAuthenticationSession(realm, client, browser.binding().tabId()))
                   .thenReturn(browser.auth()))) {
        return resource().status(handle, null, "same-origin", "cors", "empty", csrf);
      }
    }

    private WalletLoginTransportResource resource() {
      return (WalletLoginTransportResource) new WalletLoginTransportResourceFactory().create(session);
    }

    void assertDeniedAndPending(Ceremony ceremony, int status) {
      try (var proofResponse = submit(ceremony)) {
        assertEmpty(proofResponse, status);
      }
      assertPending(ceremony);
      authenticator.action(ceremony.flow());
      verify(ceremony.flow()).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
      verify(ceremony.flow(), never()).success();
      verify(ceremony.auth(), never()).setAuthenticatedUser(any());
      assertNull(ceremony.auth().getClientNote(COMPLETE_NOTE));
      assertPending(ceremony);
    }

    void assertPending(Ceremony ceremony) {
      assertEquals(ceremony.pending(), readback.load(ceremony.handle()).orElseThrow());
      assertTrue(readback.getAccepted(ceremony.handle(), ceremony.binding()).isEmpty());
      assertFalse(readback.callbackGateAvailable(ceremony.handle(), ceremony.binding()));
      try (var response = status(ceremony, ceremony.handle(), ceremony.pending().csrfToken())) {
        assertEquals(200, response.getStatus());
        assertEquals(Map.of("status", "pending"), response.getEntity());
        assertNull(response.getLocation());
      }
    }

    void assertAccepted(Ceremony ceremony) throws Exception {
      var pending = ceremony.pending();
      assertTrue(readback.load(ceremony.handle()).isEmpty());
      assertEquals(new WalletLoginTransactionStore.AcceptedTransaction(IDENTITY, base64(rawKey(ownerKey)),
              HexFormat.of().formatHex(sha256(ceremony.proof())), pending.binding(), pending.intent(),
              pending.accountAction(), pending.accountRequestId(), pending.accountRequestJti(),
              pending.accountRequestExpires()),
          readback.getAccepted(ceremony.handle(), pending.binding()).orElseThrow());
      assertTrue(readback.callbackGateAvailable(ceremony.handle(), pending.binding()));
      try (var response = status(ceremony, ceremony.handle(), pending.csrfToken())) {
        assertEquals(200, response.getStatus());
        assertEquals(Map.of("status", "accepted", "callback", ceremony.actionUrl().toASCIIString()),
            response.getEntity());
        assertNull(response.getLocation());
      }
    }

    void resume(Ceremony ceremony, UserModel user) {
      assertNull(ceremony.auth().getClientNote(COMPLETE_NOTE));
      verify(ceremony.auth(), never()).setAuthenticatedUser(any());
      authenticator.action(ceremony.flow());
      verify(ceremony.auth()).setAuthenticatedUser(user);
      verify(ceremony.flow()).success();
      verify(ceremony.flow(), never()).failure(any(AuthenticationFlowError.class));
      assertEquals("true", ceremony.auth().getClientNote(COMPLETE_NOTE));
      assertEquals(ceremony.request().state(), ceremony.auth().getClientNote("state"));
      assertNull(ceremony.auth().getAuthNote(HANDLE_NOTE));
      assertFalse(readback.callbackGateAvailable(ceremony.handle(), ceremony.binding()));
    }
  }
}
