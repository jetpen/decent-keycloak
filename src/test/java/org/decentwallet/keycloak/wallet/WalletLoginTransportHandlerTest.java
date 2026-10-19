package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.Test;
import org.keycloak.models.SingleUseObjectProvider;

final class WalletLoginTransportHandlerTest {
  private static final String IDP_ORIGIN = "https://idp.example";
  private static final String WALLET_ORIGIN = "https://wallet.example";
  private static final WalletLoginTransactionStore.Binding BINDING = new WalletLoginTransactionStore.Binding(
      "realm-id", "client-id", "root-session-id", "tab-id", "https://site.example/callback", IDP_ORIGIN);

  @Test
  void emptyJsonApiResponsesDeclareMediaTypeForKeycloakFilters() {
    assertEquals("application/json; charset=utf-8",
        WalletLoginTransportHandler.HttpResult.empty(413).headers().get("Content-Type"));
  }

  @Test
  void normalizesExplicitDefaultHttpsPortToTheSameTrustedOrigin() {
    assertTrue(WalletLoginTransportHandler.sameOrigin("https://wallet.example:443", WALLET_ORIGIN));
    assertTrue(WalletLoginTransportHandler.sameOrigin("https://idp.example:443", IDP_ORIGIN));
  }

  @Test
  void challengeTransportFailsClosedIfNoWalletOriginIsConfigured() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, null, IDP_ORIGIN);

    assertEquals(403, handler.getChallenge(issued.handle(), WALLET_ORIGIN, "cross-site", IDP_ORIGIN).status());
    assertEquals(403, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), new byte[] {1}, IDP_ORIGIN).status());
  }

  @Test
  void walletChallengeResponseMatchesTheApprovedEnvelopeFields() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN, IDP_ORIGIN,
        identityId -> true);

    var response = handler.getChallenge(issued.handle(), null, null, IDP_ORIGIN);

    assertEquals(Map.of("profile", WalletLoginProof.PROFILE,
        "challenge", issued.challenge(), "csrf_token", issued.csrfToken()), response.body());
  }

  @Test
  void nativeWalletCanReadChallengeWithoutBrowserMetadata() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN, IDP_ORIGIN);

    var response = handler.getChallenge(issued.handle(), null, null, IDP_ORIGIN);

    assertEquals(200, response.status());
    assertEquals(Map.of("profile", WalletLoginProof.PROFILE,
        "challenge", issued.challenge(), "csrf_token", issued.csrfToken()), response.body());
    assertEquals("no-store", response.headers().get("Cache-Control"));
  }

  @Test
  void rejectsChallengeGetWithPartialBrowserMetadata() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN, IDP_ORIGIN);

    assertEquals(403, handler.getChallenge(issued.handle(), WALLET_ORIGIN, null, IDP_ORIGIN).status());
    assertEquals(403, handler.getChallenge(issued.handle(), null, "cross-site", IDP_ORIGIN).status());
    assertTrue(store.load(issued.handle()).isPresent());
  }

  @Test
  void browserWalletRequestsRejectNavigationAndNonEmptyFetchDestinations() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN, IDP_ORIGIN);

    assertEquals(403, handler.getChallenge(issued.handle(), WALLET_ORIGIN, "cross-site",
        "navigate", "document", IDP_ORIGIN).status());
    assertEquals(403, handler.getChallenge(issued.handle(), WALLET_ORIGIN, "cross-site",
        "cors", "document", IDP_ORIGIN).status());
    assertEquals(200, handler.getChallenge(issued.handle(), WALLET_ORIGIN, "cross-site",
        "cors", "empty", IDP_ORIGIN).status());
  }

  @Test
  void returnsReadOnlyChallengeAndCsrfOnlyToExactWalletOrigin() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN);

    var response = handler.getChallenge(issued.handle(), WALLET_ORIGIN, "cross-site", IDP_ORIGIN);

    assertEquals(200, response.status());
    assertEquals(Map.of("profile", WalletLoginProof.PROFILE,
        "challenge", issued.challenge(), "csrf_token", issued.csrfToken()), response.body());
    assertEquals("no-store", response.headers().get("Cache-Control"));
    assertEquals(403, handler.getChallenge(issued.handle(), "https://evil.example", "cross-site", IDP_ORIGIN).status());
    assertEquals(403, handler.getChallenge(issued.handle(), WALLET_ORIGIN, "none", IDP_ORIGIN).status());
    assertEquals(404, handler.getChallenge(issued.handle(), WALLET_ORIGIN, "cross-site", "https://other-idp.example").status());
  }

  @Test
  void challengeGetRejectsPartialBrowserMetadataButPermitsNativeRequest() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN, IDP_ORIGIN);

    var nativeResponse = handler.getChallenge(issued.handle(), null, null, IDP_ORIGIN);
    var partialOrigin = handler.getChallenge(issued.handle(), WALLET_ORIGIN, null, IDP_ORIGIN);
    var partialFetch = handler.getChallenge(issued.handle(), null, "cross-site", IDP_ORIGIN);

    assertEquals(200, nativeResponse.status());
    assertEquals(403, partialOrigin.status());
    assertEquals(403, partialFetch.status());
    assertTrue(partialOrigin.body().isEmpty());
    assertTrue(partialFetch.body().isEmpty());
    assertTrue(store.load(issued.handle()).isPresent());
  }

  @Test
  void rejectsWrongOriginFetchMetadataAndHostWithoutDisclosingChallenge() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN);

    assertEquals(403, handler.getChallenge(issued.handle(), "https://evil.example", "cross-site", IDP_ORIGIN).status());
    assertEquals(403, handler.getChallenge(issued.handle(), WALLET_ORIGIN, "none", IDP_ORIGIN).status());
    assertEquals(404, handler.getChallenge(issued.handle(), WALLET_ORIGIN, "cross-site", "https://other-idp.example").status());
  }

  @Test
  void dialWarningOnExactRegistryMissMapsTo503AndKeepsPendingWithoutReceiptOrCallback() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String identity = "mailto:resolver-unavailable@example.org";
    byte[] proof = signedProof(issued.challenge(), identity, keyPair);
    var resolverExecutable = Files.createTempFile("identity-unavailable-stub-", ".sh");
    try {
      String exactKey = ProcessIdentityResolver.exactRegistryObjectKeyHex(identity);
      String output = String.join(System.lineSeparator(),
          "Failed to open TCP stream: all attempts to connect to /ip4/127.0.0.1/tcp/9000 failed",
          "Value not found for key /decent-registry/identity/" + exactKey, "not found", "");
      String encoded = Base64.getEncoder().encodeToString(output.getBytes(StandardCharsets.UTF_8));
      Files.writeString(resolverExecutable, String.join(System.lineSeparator(),
          "#!/bin/sh", "printf '%s' '" + encoded + "' | base64 -d", "exit 1", ""));
      resolverExecutable.toFile().setExecutable(true);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, resolverExecutable.toString());
      var resolverFailure = assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact(identity));
      assertEquals("Identity lookup failed", resolverFailure.getMessage());
      assertNull(resolverFailure.getCause());
      WalletLoginIdentityResolver identityResolver = resolver::resolveExact;
      var handler = new WalletLoginTransportHandler(store, identityResolver, WALLET_ORIGIN, IDP_ORIGIN,
          exact -> true);

      var response = handler.submitProof(issued.handle(), null, null, null, null,
          "application/json", null, proof, IDP_ORIGIN);

      assertEquals(503, response.status());
      assertTrue(store.load(issued.handle()).isPresent());
      assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
      assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
    } finally {
      Files.deleteIfExists(resolverExecutable);
    }
  }

  @Test
  void factoryWithoutRegistryConfigurationReturnsUnavailableNotIdentityAbsence() throws Exception {
    var provider = new MemoryStore();
    var store = new WalletLoginTransactionStore(provider, new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String identity = "mailto:resolver-unconfigured@example.org";
    byte[] proof = signedProof(issued.challenge(), identity, keyPair);

    var session = mock(org.keycloak.models.KeycloakSession.class);
    var context = mock(org.keycloak.models.KeycloakContext.class);
    var uriInfo = mock(org.keycloak.models.KeycloakUriInfo.class);
    var realm = mock(org.keycloak.models.RealmModel.class);
    when(session.getContext()).thenReturn(context);
    when(session.singleUseObjects()).thenReturn(provider);
    when(context.getRealm()).thenReturn(realm);
    when(context.getUri()).thenReturn(uriInfo);
    when(uriInfo.getBaseUri()).thenReturn(java.net.URI.create(IDP_ORIGIN + "/auth/"));
    when(uriInfo.getQueryParameters()).thenReturn(new jakarta.ws.rs.core.MultivaluedHashMap<>());
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_WALLET_ORIGIN)).thenReturn(WALLET_ORIGIN);
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_REGISTRY_BOOTSTRAP)).thenReturn(null);
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_REGISTRY_CLIENT_PORT)).thenReturn(null);
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_IDP_ORIGIN)).thenReturn(null);
    when(realm.isRegistrationAllowed()).thenReturn(false);

    var resource = (WalletLoginTransportResource) new WalletLoginTransportResourceFactory().create(session);
    var handlerField = WalletLoginTransportResource.class.getDeclaredField("handler");
    handlerField.setAccessible(true);
    var handler = (WalletLoginTransportHandler) handlerField.get(resource);

    var response = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(503, response.status());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void exactRegistryMissMapsTo401AndKeepsPendingWithoutReceiptOrCallback() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String identity = "mailto:identity-absent@example.org";
    byte[] proof = signedProof(issued.challenge(), identity, keyPair);
    var resolverExecutable = Files.createTempFile("identity-not-found-stub-", ".sh");
    try {
      String expectedKey = ProcessIdentityResolver.exactRegistryObjectKeyHex(identity);
      String output = "Value not found for key /decent-registry/identity/" + expectedKey + "\nnot found\n";
      String encoded = Base64.getEncoder().encodeToString(output.getBytes(StandardCharsets.UTF_8));
      Files.writeString(resolverExecutable, "#!/bin/sh\nprintf '%s' '" + encoded + "' | base64 -d\nexit 1\n");
      resolverExecutable.toFile().setExecutable(true);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, resolverExecutable.toString());
      WalletLoginIdentityResolver identityResolver = resolver::resolveExact;
      var handler = new WalletLoginTransportHandler(store, identityResolver, WALLET_ORIGIN, IDP_ORIGIN,
          exact -> true);

      var response = handler.submitProof(issued.handle(), null, null, null, null,
          "application/json", null, proof, IDP_ORIGIN);

      assertEquals(401, response.status());
      assertTrue(store.load(issued.handle()).isPresent());
      assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
      assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
    } finally {
      Files.deleteIfExists(resolverExecutable);
    }
  }

  @Test
  void signupPendingIntentCanBeResumedAfterWalletProof() throws Exception {
    var keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:signup@example.org", keyPair);
    var identityLookups = new java.util.concurrent.atomic.AtomicInteger();
    var provisions = new java.util.concurrent.atomic.AtomicInteger();
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) {
        return provisions.get() > 0;
      }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) {
        return false;
      }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        provisions.incrementAndGet();
        var user = org.mockito.Mockito.mock(org.keycloak.models.UserModel.class);
        org.mockito.Mockito.when(user.isEnabled()).thenReturn(true);
        return user;
      }
    };
    var handler = new WalletLoginTransportHandler(store, exact -> {
      identityLookups.incrementAndGet();
      return new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair));
    }, WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    var rejected = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(202, rejected.status());
    assertEquals(1, identityLookups.get());
    assertEquals(1, provisions.get());
    assertTrue(store.load(issued.handle()).isEmpty());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isPresent());
    var signupStatus = handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, BINDING);
    assertEquals(200, signupStatus.status());
    assertEquals(Map.of("status", "accepted"), signupStatus.body());
  }

  @Test
  void requestCorrelationIdIsOpaqueStableHandleDigest() throws Exception {
    String handle = "opaque-transaction-handle";
    String first = WalletLoginTransportHandler.requestCorrelationId(handle);
    String second = WalletLoginTransportHandler.requestCorrelationId(handle);

    assertEquals(32, first.length());
    assertTrue(first.matches("[0-9a-f]{32}"));
    assertEquals(first, second);
    assertFalse(first.contains(handle));
  }

  @Test
  void accountPolicyDecisionLogIncludesOnlyOpaqueRequestCorrelationId() throws Exception {
    var source = java.nio.file.Files.readString(java.nio.file.Path.of(
        "src/main/java/org/decentwallet/keycloak/wallet/WalletLoginTransportHandler.java"));
    var start = source.indexOf("if (intent != WalletLoginTransactionStore.Intent.SIGNUP || !acceptSignup || occupied)");
    var end = source.indexOf("return HttpResult.empty(403);", start);
    var log = source.substring(start, end);

    assertTrue(start >= 0 && end > start);
    assertTrue(log.contains("Wallet account policy rejected proof (request=%s"));
    assertFalse(log.contains("proof.identityId()"));
    assertFalse(log.contains("proof.signature()"));
    assertFalse(log.contains("pending.get().csrfToken()"));
  }

  @Test
  void resolverAndMappingLogsIncludeOnlyOpaqueRequestCorrelationId() throws Exception {
    var source = java.nio.file.Files.readString(java.nio.file.Path.of(
        "src/main/java/org/decentwallet/keycloak/wallet/WalletLoginTransportHandler.java"));
    assertTrue(source.contains("Wallet Identity resolver unavailable (request=%s, %s)"));
    assertTrue(source.contains("Wallet account mapping lookup unavailable (request=%s, %s)"));
    assertFalse(source.contains("Wallet Identity resolver unavailable (%s)"));
  }

  @Test
  void signupProvisionedAccountIsNotCompensatedWhenConsumeLoses() throws Exception {
    var keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var provider = new MemoryStore();
    var issued = new WalletLoginTransactionStore(provider, new java.security.SecureRandom(), Clock.systemUTC())
        .issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:race@example.org", keyPair);
    var provisionCalls = new java.util.concurrent.atomic.AtomicInteger();
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      private volatile boolean provisioned;
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return provisioned; }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) { return provisioned; }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) throws Exception {
        provisionCalls.incrementAndGet();
        provisioned = true;
        provider.remove(transactionKey(issued.handle()));
        var user = org.mockito.Mockito.mock(org.keycloak.models.UserModel.class);
        org.mockito.Mockito.when(user.isEnabled()).thenReturn(true);
        return user;
      }
    };
    var store = new WalletLoginTransactionStore(provider, new java.security.SecureRandom(), Clock.systemUTC());
    var handler = new WalletLoginTransportHandler(store, exact ->
        new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)), WALLET_ORIGIN,
        IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(409, result.status());
    assertEquals(1, provisionCalls.get());
    assertTrue(accounts.hasUniqueEnabledUser("mailto:race@example.org"));
    assertTrue(provider.entries.keySet().stream().noneMatch(key -> key.startsWith("decent-wallet-login-v1:accepted:")));
    assertTrue(provider.entries.keySet().stream().noneMatch(key -> key.startsWith("decent-wallet-login-v1:callback:")));
    assertFalse(store.getAccepted(issued.handle(), BINDING).isPresent());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void acceptedReceiptWriteFailureLeavesCreatedAccountBeforePendingConsume() throws Exception {
    var keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var provider = new FailingAcceptedReceiptStore();
    var store = new WalletLoginTransactionStore(provider, new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:receipt-failure@example.org", keyPair);
    var provisionCalls = new java.util.concurrent.atomic.AtomicInteger();
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      private volatile boolean provisioned;
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return provisioned; }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) { return provisioned; }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        provisionCalls.incrementAndGet();
        provisioned = true;
        var user = org.mockito.Mockito.mock(org.keycloak.models.UserModel.class);
        org.mockito.Mockito.when(user.isEnabled()).thenReturn(true);
        return user;
      }
    };
    var handler = new WalletLoginTransportHandler(store, exact ->
        new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)), WALLET_ORIGIN,
        IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(503, result.status());
    assertEquals(1, provisionCalls.get());
    assertTrue(store.load(issued.handle()).isEmpty());
    assertFalse(store.getAccepted(issued.handle(), BINDING).isPresent());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
    assertTrue(accounts.hasUniqueEnabledUser("mailto:receipt-failure@example.org"));
  }
  @Test
  void signupProofCanBeResumedOnlyByTheOriginalKeycloakActionUrl() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String identity = "mailto:signup-callback@example.org";
    byte[] proof = signedProof(issued.challenge(), identity, keyPair);
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      private boolean provisioned;
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return provisioned; }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) { return provisioned; }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        provisioned = true;
        var user = org.mockito.Mockito.mock(org.keycloak.models.UserModel.class);
        org.mockito.Mockito.when(user.isEnabled()).thenReturn(true);
        return user;
      }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);
    assertEquals(202, handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN).status());
    var available = handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, BINDING);
    assertEquals(200, available.status());
    assertEquals(Map.of("status", "accepted"), available.body());
    assertTrue(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void validRegistryProofRejectsDisabledExactMappingWithoutProvisioning() throws Exception {
    var keyPair = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), java.time.Clock.systemUTC());
    var issued = store.issue(BINDING);
    String identity = "mailto:disabled@example.org";
    byte[] proof = signedProof(issued.challenge(), identity, keyPair);
    var provisionCalls = new java.util.concurrent.atomic.AtomicInteger();
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return false; }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) { return true; }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        provisionCalls.incrementAndGet();
        return null;
      }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN, WalletLoginTransactionStore.Intent.SIGNUP);

    assertEquals(403, result.status());
    assertEquals(0, provisionCalls.get());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
  }

  @Test
  void validRegistryProofRejectsAmbiguousMappingsWithoutProvisioning() throws Exception {
    var keyPair = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), java.time.Clock.systemUTC());
    var issued = store.issue(BINDING);
    String identity = "mailto:duplicate@example.org";
    byte[] proof = signedProof(issued.challenge(), identity, keyPair);
    var provisionCalls = new java.util.concurrent.atomic.AtomicInteger();
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return false; }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) { return false; }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        provisionCalls.incrementAndGet();
        return null;
      }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN, WalletLoginTransactionStore.Intent.SIGNUP);

    assertEquals(403, result.status());
    assertEquals(0, provisionCalls.get());
    assertTrue(store.load(issued.handle()).isPresent());
  }


  @Test
  void provisionFailureLeavesSignupTransactionPendingAndUnaccepted() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:new@example.org", keyPair);
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return false; }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        throw new IllegalStateException("provisioning unavailable");
      }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    assertEquals(503, handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN, WalletLoginTransactionStore.Intent.SIGNUP).status());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
  }

  @Test
  void verifiesExactCurrentRegistryKeyAndConsumesTransactionOnlyAfterValidSignature() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String identity = "mailto:alice@example.org";
    byte[] proof = signedProof(issued.challenge(), identity, keyPair);
    WalletLoginIdentityResolver resolver = exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair));
    var handler = new WalletLoginTransportHandler(store, resolver, WALLET_ORIGIN, IDP_ORIGIN,
        exact -> true);

    var accepted = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
        "application/json", issued.csrfToken(), proof, IDP_ORIGIN);

    assertEquals(202, accepted.status());
    assertEquals(Map.of("status", "pending"), accepted.body());
    assertTrue(store.load(issued.handle()).isEmpty());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isPresent());
    var result = store.takeAccepted(issued.handle(), BINDING).orElseThrow();
    assertEquals(identity, result.identityId());
    assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(rawKey(keyPair)), result.publicKey());
    assertTrue(store.takeAccepted(issued.handle(), BINDING).isEmpty());
  }

  @Test
  void identicalProofRetryObservesAcceptedStatusWithoutASecondResolverOrCallback() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var lookups = new java.util.concurrent.atomic.AtomicInteger();
    var handler = new WalletLoginTransportHandler(store, exact -> {
      lookups.incrementAndGet();
      return new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair));
    }, WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    var first = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN);
    var retry = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN);
    byte[] changedEncoding = (new String(proof, StandardCharsets.UTF_8) + " ").getBytes(StandardCharsets.UTF_8);
    var differentProof = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), changedEncoding, IDP_ORIGIN);
    assertTrue(store.takeAccepted(issued.handle(), BINDING).isPresent());
    var retryAfterCallback = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN);

    assertEquals(202, first.status());
    assertEquals(Map.of("status", "accepted"), retry.body());
    assertEquals(409, differentProof.status());
    assertEquals(Map.of("status", "accepted"), retryAfterCallback.body());
    assertTrue(store.takeAccepted(issued.handle(), BINDING).isEmpty());
    assertEquals(1, lookups.get());
  }

  @Test
  void nativeWalletCanSubmitSignedProofWithoutOriginOrBrowserCsrf() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    var accepted = handler.submitProof(issued.handle(), null, null, "application/json", null,
        proof, IDP_ORIGIN);

    assertEquals(202, accepted.status());
    assertEquals(Map.of("status", "pending"), accepted.body());
    assertTrue(store.load(issued.handle()).isEmpty());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isPresent());
  }

  @Test
  void rejectsNativeProofRequestsThatIncludeAnyBrowserOrCsrfMetadata() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    assertEquals(403, handler.submitProof(issued.handle(), null, "cross-site", "application/json",
        null, proof, IDP_ORIGIN).status());
    assertEquals(403, handler.submitProof(issued.handle(), WALLET_ORIGIN, null, "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN).status());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
  }

  @Test
  void deniesWrongRealmClientTabAndSessionStatusRequests() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN, IDP_ORIGIN);
    var wrongClient = new WalletLoginTransactionStore.Binding("realm-id", "not-the-wallet-client",
        BINDING.rootSessionId(), BINDING.tabId(), BINDING.redirectUri(), IDP_ORIGIN);
    var wrongTab = new WalletLoginTransactionStore.Binding("realm-id", BINDING.clientId(),
        BINDING.rootSessionId(), "not-the-initiating-tab", BINDING.redirectUri(), IDP_ORIGIN);
    var wrongSession = new WalletLoginTransactionStore.Binding("realm-id", BINDING.clientId(),
        "not-the-initiating-session", BINDING.tabId(), BINDING.redirectUri(), IDP_ORIGIN);
    var wrongRealm = new WalletLoginTransactionStore.Binding("not-the-wallet-realm", BINDING.clientId(),
        BINDING.rootSessionId(), BINDING.tabId(), BINDING.redirectUri(), IDP_ORIGIN);

    assertEquals(404, handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, wrongClient).status());
    assertEquals(404, handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, wrongTab).status());
    assertEquals(404, handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, wrongSession).status());
    assertEquals(404, handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, wrongRealm).status());
    assertEquals(200, handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, BINDING).status());
  }

  @Test
  void transactionConsumeWinnerHasNoAcceptedReceiptWhenReceiptPublicationFails() {
    var provider = new FailingAcceptedReceiptStore();
    var store = new WalletLoginTransactionStore(provider, new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var consumed = store.consume(issued.handle(), BINDING, issued.challenge(), issued.csrfToken());

    assertTrue(consumed.isPresent());
    assertThrows(IllegalStateException.class, () -> store.markAccepted(issued.handle(), BINDING,
        "proof-digest", "mailto:alice@example.org", "AA", issued.csrfToken()));
    assertTrue(store.load(issued.handle()).isEmpty());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void callbackGateWriteFailurePublishesNoAcceptedReceipt() {
    var provider = new FailingCallbackGateStore();
    var store = new WalletLoginTransactionStore(provider, new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    assertTrue(store.consume(issued.handle(), BINDING, issued.challenge(), issued.csrfToken()).isPresent());

    assertThrows(IllegalStateException.class, () -> store.markAccepted(issued.handle(), BINDING,
        "proof-digest", "mailto:alice@example.org", "AA", issued.csrfToken()));
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void rejectsSubmissionAfterPendingTransactionExpiresWithoutReceipt() throws Exception {
    var clock = new MutableClock(java.time.Instant.parse("2026-10-12T00:00:00Z"));
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), clock);
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var lookups = new java.util.concurrent.atomic.AtomicInteger();
    var handler = new WalletLoginTransportHandler(store, exact -> {
      lookups.incrementAndGet();
      return new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair));
    }, WALLET_ORIGIN, IDP_ORIGIN, exact -> true);
    clock.advanceSeconds(WalletLoginTransactionStore.TRANSACTION_LIFESPAN_SECONDS);

    var result = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN);

    assertEquals(404, result.status());
    assertEquals(0, lookups.get());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
  }

  @Test
  void receiptPublicationFailureReturnsUnavailableAndCannotBePolledAsAccepted() throws Exception {
    var provider = new FailingAcceptedReceiptStore();
    var store = new WalletLoginTransactionStore(provider, new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    var response = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN);
    var status = handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, BINDING);

    assertEquals(503, response.status());
    assertTrue(store.load(issued.handle()).isEmpty(), "winner nonce is consumed even when receipt write fails");
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
    assertEquals(404, status.status());
  }

  @Test
  void callbackGatePublicationFailureReturnsUnavailableWithoutReceiptOrCallback() throws Exception {
    var provider = new FailingCallbackGateStore();
    var store = new WalletLoginTransactionStore(provider, new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    var response = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN);
    var status = handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, BINDING);

    assertEquals(503, response.status());
    assertTrue(store.load(issued.handle()).isEmpty());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
    assertEquals(404, status.status());
  }

  @Test
  void invalidProofThrottleReturns429BeforeResolverAndLeavesTransactionPending() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] validProof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var lookups = new java.util.concurrent.atomic.AtomicInteger();
    var handler = new WalletLoginTransportHandler(store, exact -> {
      lookups.incrementAndGet();
      return new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair));
    }, WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    for (int attempt = 0; attempt < 5; attempt++) {
      assertEquals(400, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
          "application/json", issued.csrfToken(), new byte[] {'{'}, IDP_ORIGIN).status());
    }
    var throttled = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
        "application/json", issued.csrfToken(), validProof, IDP_ORIGIN);
    var status = handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, BINDING);

    assertEquals(429, throttled.status());
    assertEquals(0, lookups.get());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
    assertEquals(200, status.status());
    assertEquals(Map.of("status", "pending"), status.body());
  }

  @Test
  void unmappedLocalAccountRejectsProofBeforeConsumingChallenge() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> false);

    var rejected = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN);

    assertEquals(403, rejected.status());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
  }

  @Test
  void signupAccountLookupFailureReturnsUnavailableAndLeavesTransactionPending() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:account-lookup-outage@example.org", keyPair);
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) {
        throw new IllegalStateException("account lookup unavailable");
      }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(503, result.status());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void enabledAccountCandidateCapFailsClosedForSignupHandler() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:enabled-cap@example.org", keyPair);
    var realm = org.mockito.Mockito.mock(org.keycloak.models.RealmModel.class);
    var users = org.mockito.Mockito.mock(org.keycloak.models.UserProvider.class);
    org.mockito.Mockito.when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, "mailto:enabled-cap@example.org"))
        .thenReturn(java.util.stream.IntStream.range(0, 65)
            .mapToObj(index -> org.mockito.Mockito.mock(org.keycloak.models.UserModel.class)));
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) {
        return WalletLoginAccountMapping.hasUniqueEnabledMapping(users, realm, exactIdentityId);
      }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) {
        return WalletLoginAccountMapping.hasUniqueMappingIncludingDisabled(users, realm, exactIdentityId);
      }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        return WalletLoginAccountMapping.ensureEnabledUser(users, realm, exactIdentityId, true);
      }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(503, result.status());
    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).addUser(
        org.mockito.ArgumentMatchers.eq(realm), org.mockito.ArgumentMatchers.isNull(),
        org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.eq(true),
        org.mockito.ArgumentMatchers.eq(true));
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void nullOccupancySearchReturnsUnavailableBeforeSignupAndLeavesTransactionPending() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:occupancy-null-stream@example.org", keyPair);
    var createCalls = new java.util.concurrent.atomic.AtomicInteger();
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return false; }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) {
        throw new IllegalStateException("identity mapping lookup unavailable");
      }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        createCalls.incrementAndGet();
        return org.mockito.Mockito.mock(org.keycloak.models.UserModel.class);
      }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(503, result.status());
    assertEquals(0, createCalls.get());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void signupOccupancyCandidateCapReturnsUnavailableBeforeCreateAndLeavesTransactionPending() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:occupancy-cap@example.org", keyPair);
    var realm = org.mockito.Mockito.mock(org.keycloak.models.RealmModel.class);
    var users = org.mockito.Mockito.mock(org.keycloak.models.UserProvider.class);
    var createCalls = new java.util.concurrent.atomic.AtomicInteger();
    org.mockito.Mockito.when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, "mailto:occupancy-cap@example.org"))
        .thenReturn(java.util.stream.IntStream.range(0, 65)
            .mapToObj(index -> org.mockito.Mockito.mock(org.keycloak.models.UserModel.class)));
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return false; }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) {
        return WalletLoginAccountMapping.hasUniqueMappingIncludingDisabled(users, realm, exactIdentityId);
      }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        createCalls.incrementAndGet();
        return org.mockito.Mockito.mock(org.keycloak.models.UserModel.class);
      }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(503, result.status());
    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).addUser(
        org.mockito.ArgumentMatchers.eq(realm), org.mockito.ArgumentMatchers.isNull(),
        org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.eq(true),
        org.mockito.ArgumentMatchers.eq(true));
    assertEquals(0, createCalls.get());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void signupProvisioningNonSuccessDoesNotConsumeOrAcceptTransaction() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:ambiguous-signup@example.org", keyPair);
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return false; }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) { return false; }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) { return null; }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(503, result.status());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void signupProvisioningReadBackFailureIsUnavailableAndLeavesPendingTransaction() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING, WalletLoginTransactionStore.Intent.SIGNUP);
    byte[] proof = signedProof(issued.challenge(), "mailto:readback-outage@example.org", keyPair);
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String exactIdentityId) { return false; }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String exactIdentityId) { return false; }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String exactIdentityId) {
        throw new IllegalStateException("identity mapping read-back unavailable");
      }
    };
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, accounts, true);

    var result = handler.submitProof(issued.handle(), null, null, null, null,
        "application/json", null, proof, IDP_ORIGIN);

    assertEquals(503, result.status());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.getAccepted(issued.handle(), BINDING).isEmpty());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
  }

  @Test
  void unavailableOrMismatchedRegistryIdentityFailsClosedAndDoesNotConsume() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var unavailable = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN);
    assertEquals(503, unavailable.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
        "application/json", issued.csrfToken(), proof, IDP_ORIGIN).status());
    var mismatch = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey("mailto:Alice@example.org", rawKey(keyPair)), WALLET_ORIGIN);
    assertEquals(401, mismatch.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
        "application/json", issued.csrfToken(), proof, IDP_ORIGIN).status());
    assertTrue(store.load(issued.handle()).isPresent());
  }

  @Test
  void sameOriginBrowserCanPollStatusWithoutAnOriginHeaderButMustPresentCsrf() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var handler = new WalletLoginTransportHandler(store, null, WALLET_ORIGIN, IDP_ORIGIN);

    var pending = handler.getStatus(issued.handle(), null, "same-origin", issued.csrfToken(), IDP_ORIGIN, BINDING);
    var rejected = handler.getStatus(issued.handle(), null, "same-origin", "wrong", IDP_ORIGIN, BINDING);
    var crossSite = handler.getStatus(issued.handle(), "https://evil.example", "same-origin", issued.csrfToken(), IDP_ORIGIN, BINDING);

    assertEquals(200, pending.status());
    assertEquals(Map.of("status", "pending"), pending.body());
    assertEquals(403, rejected.status());
    assertEquals(403, crossSite.status());
  }

  @Test
  void acceptedReceiptStatusIsStillBoundToCsrfAndSession() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> true);
    assertEquals(202, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN).status());

    var accepted = handler.getStatus(issued.handle(), null, "same-origin", issued.csrfToken(), IDP_ORIGIN, BINDING);
    var badCsrf = handler.getStatus(issued.handle(), null, "same-origin", "bad", IDP_ORIGIN, BINDING);

    assertEquals(200, accepted.status());
    assertEquals(403, badCsrf.status());
  }

  @Test
  void acceptedStatusRequiresTheSameSessionBinding() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> true);
    handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN);
    var wrong = new WalletLoginTransactionStore.Binding("realm-id", "other-client", "root-session-id",
        "tab-id", BINDING.redirectUri(), IDP_ORIGIN);

    assertEquals(404, handler.getStatus(issued.handle(), null, "same-origin", issued.csrfToken(), IDP_ORIGIN, wrong).status());
  }

  @Test
  void acceptedProofCanBeObservedByTheBoundBrowserUntilItConsumesReceipt() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:alice@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> true);
    var submitted = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
        "application/json", issued.csrfToken(), proof, IDP_ORIGIN);

    var observed = handler.getStatus(issued.handle(), null, "same-origin", issued.csrfToken(), IDP_ORIGIN, BINDING);
    var wrongCsrf = handler.getStatus(issued.handle(), null, "same-origin", "invalid", IDP_ORIGIN, BINDING);

    assertEquals(202, submitted.status());
    assertEquals(200, observed.status());
    assertEquals(Map.of("status", "accepted"), observed.body());
    assertEquals(403, wrongCsrf.status());
    assertTrue(store.takeAccepted(issued.handle(), BINDING).isPresent());
  }

  @Test
  void statusStopsAdvertisingCallbackAfterItsOneUseGateIsConsumed() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    assertTrue(store.consume(issued.handle(), BINDING, issued.challenge(), issued.csrfToken()).isPresent());
    store.markAccepted(issued.handle(), BINDING, "proof-digest", "mailto:alice@example.org", "AA", issued.csrfToken());
    var handler = new WalletLoginTransportHandler(store, exact -> null, WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    assertEquals(200, handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, BINDING).status());
    assertTrue(store.takeAccepted(issued.handle(), BINDING).isPresent());

    assertEquals(404, handler.getStatus(issued.handle(), null, "same-origin", "cors", "empty",
        issued.csrfToken(), IDP_ORIGIN, BINDING).status());
  }

  @Test
  void serializesExpensiveIdentityResolutionPerTransaction() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:missing@example.org", keyPair);
    var enteredResolver = new java.util.concurrent.CountDownLatch(1);
    var releaseResolver = new java.util.concurrent.CountDownLatch(1);
    var calls = new java.util.concurrent.atomic.AtomicInteger();
    var handler = new WalletLoginTransportHandler(store, exact -> {
      calls.incrementAndGet();
      enteredResolver.countDown();
      if (!releaseResolver.await(5, java.util.concurrent.TimeUnit.SECONDS)) {
        throw new IllegalStateException("test resolver release timed out");
      }
      return null;
    }, WALLET_ORIGIN, IDP_ORIGIN, exact -> true);
    var pool = java.util.concurrent.Executors.newSingleThreadExecutor();
    try {
      var first = pool.submit(() -> handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
          "application/json", issued.csrfToken(), proof, IDP_ORIGIN));
      assertTrue(enteredResolver.await(3, java.util.concurrent.TimeUnit.SECONDS));
      var concurrent = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
          issued.csrfToken(), proof, IDP_ORIGIN);
      assertEquals(429, concurrent.status());
      releaseResolver.countDown();
      assertEquals(401, first.get(5, java.util.concurrent.TimeUnit.SECONDS).status());
      assertEquals(1, calls.get());
      assertEquals(429, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
          issued.csrfToken(), proof, IDP_ORIGIN).status());
      assertEquals(1, calls.get());
    } finally {
      releaseResolver.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void resolverProcessThatMayStillRunBlocksTheTransactionAndBrowserClient() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var siblingBinding = new WalletLoginTransactionStore.Binding("realm-id", "client-id", "root-session-id",
        "sibling-tab", "https://site.example/callback", IDP_ORIGIN);
    var sibling = store.issue(siblingBinding);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:missing@example.org", keyPair);
    byte[] siblingProof = signedProof(sibling.challenge(), "mailto:missing@example.org", keyPair);
    var calls = new java.util.concurrent.atomic.AtomicInteger();
    var handler = new WalletLoginTransportHandler(store, exact -> {
      calls.incrementAndGet();
      throw new ProcessIdentityResolver.IdentityResolutionException("process remains alive", true);
    }, WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    assertEquals(503, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN).status());
    assertEquals(429, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN).status());
    assertTrue(store.load(sibling.handle()).isPresent());
    assertEquals(429, handler.submitProof(sibling.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        sibling.csrfToken(), siblingProof, IDP_ORIGIN).status());
    assertEquals(1, calls.get());
    org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> store.issue(BINDING));
  }

  @Test
  void resolverKillFailureStillLocksBrowserClientWhenPendingTransactionExpires() throws Exception {
    var clock = new MutableClock(java.time.Instant.parse("2026-10-12T00:00:00Z"));
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), clock);
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:missing@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store, exact -> {
      clock.advanceSeconds(301);
      throw new ProcessIdentityResolver.IdentityResolutionException("process remains alive", true);
    }, WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    assertEquals(503, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN).status());
    assertTrue(store.load(issued.handle()).isEmpty());
    var anotherTab = new WalletLoginTransactionStore.Binding("realm-id", "client-id", "root-session-id",
        "another-tab", "https://site.example/callback", IDP_ORIGIN);
    org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () -> store.issue(anotherTab));
  }

  @Test
  void unknownRegistryIdentityLookupIsRateLimitedAfterOneWindow() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:missing@example.org", keyPair);
    var lookups = new java.util.concurrent.atomic.AtomicInteger();
    var handler = new WalletLoginTransportHandler(store, exact -> {
      lookups.incrementAndGet();
      return null;
    }, WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    assertEquals(401, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
        "application/json", issued.csrfToken(), proof, IDP_ORIGIN).status());
    for (int attempt = 0; attempt < 4; attempt++) {
      assertEquals(429, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
          "application/json", issued.csrfToken(), proof, IDP_ORIGIN).status());
    }
    assertEquals(1, lookups.get());
    assertTrue(store.load(issued.handle()).isPresent());
    assertFalse(store.invalidAttemptLimitReached(issued.handle()));
  }

  @Test
  void rejectsFurtherMalformedProofsAfterFiveAttemptsWithoutConsumingTransaction() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var calls = new java.util.concurrent.atomic.AtomicInteger();
    var handler = new WalletLoginTransportHandler(store, exact -> {
      calls.incrementAndGet();
      return null;
    }, WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    for (int attempt = 0; attempt < 5; attempt++) {
      assertEquals(400, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
          "application/json", issued.csrfToken(), "{}".getBytes(StandardCharsets.UTF_8), IDP_ORIGIN).status());
    }
    var limited = handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site",
        "application/json", issued.csrfToken(), "{}".getBytes(StandardCharsets.UTF_8), IDP_ORIGIN);

    assertEquals(429, limited.status());
    assertTrue(store.load(issued.handle()).isPresent());
    assertEquals(0, calls.get());
  }

  @Test
  void malformedProofBadCsrfAndTransportAreRejectedWithoutRegistryLookup() {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var calls = new java.util.concurrent.atomic.AtomicInteger();
    WalletLoginIdentityResolver resolver = exact -> { calls.incrementAndGet(); return null; };
    var handler = new WalletLoginTransportHandler(store, resolver, WALLET_ORIGIN);
    assertEquals(400, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), "{}".getBytes(StandardCharsets.UTF_8), IDP_ORIGIN).status());
    assertEquals(415, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "text/plain",
        issued.csrfToken(), new byte[] {1}, IDP_ORIGIN).status());
    assertEquals(403, handler.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        "bad-csrf-token", new byte[] {1}, IDP_ORIGIN).status());
    assertEquals(403, handler.submitProof(issued.handle(), "https://evil.example", "cross-site", "application/json",
        issued.csrfToken(), new byte[] {1}, IDP_ORIGIN).status());
    assertEquals(0, calls.get());
    assertTrue(store.load(issued.handle()).isPresent());
  }

  @Test
  void proofForOneTransactionCannotBeSubmittedAtAnotherValidTransactionHandle() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var initiatingTransaction = store.issue(BINDING);
    var otherTransaction = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] initiatingProof = signedProof(initiatingTransaction.challenge(), "mailto:wrong-handle@example.org", keyPair);
    var handler = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> true);

    var crossHandleAttempt = handler.submitProof(otherTransaction.handle(), null, null, null, null,
        "application/json", null, initiatingProof, IDP_ORIGIN);
    var initiatingAttempt = handler.submitProof(initiatingTransaction.handle(), null, null, null, null,
        "application/json", null, initiatingProof, IDP_ORIGIN);

    assertEquals(401, crossHandleAttempt.status());
    assertEquals(202, initiatingAttempt.status());
    assertTrue(store.load(otherTransaction.handle()).isPresent());
    assertFalse(store.load(initiatingTransaction.handle()).isPresent());
    assertTrue(store.getAccepted(otherTransaction.handle(), BINDING).isEmpty());
    assertTrue(store.getAccepted(initiatingTransaction.handle(), BINDING).isPresent());
    assertFalse(store.callbackGateAvailable(otherTransaction.handle(), BINDING));
    assertTrue(store.callbackGateAvailable(initiatingTransaction.handle(), BINDING));
  }

  @Test
  void acceptedReceiptAndCallbackGateRequireExactInitiatingBinding() throws Exception {
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] proof = signedProof(issued.challenge(), "mailto:binding-check@example.org", keyPair);
    var accepted = new WalletLoginTransportHandler(store,
        exact -> new WalletIdentityKeyResolver.ResolvedIdentityKey(exact, rawKey(keyPair)),
        WALLET_ORIGIN, IDP_ORIGIN, exact -> true);
    var result = accepted.submitProof(issued.handle(), WALLET_ORIGIN, "cross-site", "application/json",
        issued.csrfToken(), proof, IDP_ORIGIN);
    assertEquals(202, result.status());
    assertFalse(store.load(issued.handle()).isPresent());

    var otherBindings = java.util.List.of(
        new WalletLoginTransactionStore.Binding("other-realm", BINDING.clientId(), BINDING.rootSessionId(),
            BINDING.tabId(), BINDING.redirectUri(), BINDING.canonicalOrigin()),
        new WalletLoginTransactionStore.Binding(BINDING.realmId(), "other-client", BINDING.rootSessionId(),
            BINDING.tabId(), BINDING.redirectUri(), BINDING.canonicalOrigin()),
        new WalletLoginTransactionStore.Binding(BINDING.realmId(), BINDING.clientId(), "other-root-session",
            BINDING.tabId(), BINDING.redirectUri(), BINDING.canonicalOrigin()),
        new WalletLoginTransactionStore.Binding(BINDING.realmId(), BINDING.clientId(), BINDING.rootSessionId(),
            "other-tab", BINDING.redirectUri(), BINDING.canonicalOrigin()),
        new WalletLoginTransactionStore.Binding(BINDING.realmId(), BINDING.clientId(), BINDING.rootSessionId(),
            BINDING.tabId(), "https://other.example/callback", BINDING.canonicalOrigin()),
        new WalletLoginTransactionStore.Binding(BINDING.realmId(), BINDING.clientId(), BINDING.rootSessionId(),
            BINDING.tabId(), BINDING.redirectUri(), "https://other-idp.example"));

    for (var otherBinding : otherBindings) {
      assertTrue(store.getAccepted(issued.handle(), otherBinding).isEmpty());
      assertFalse(store.callbackGateAvailable(issued.handle(), otherBinding));
      assertTrue(store.takeAccepted(issued.handle(), otherBinding).isEmpty());
      assertTrue(store.callbackGateAvailable(issued.handle(), BINDING));
    }
    assertTrue(store.getAccepted(issued.handle(), BINDING).isPresent());
    assertTrue(store.callbackGateAvailable(issued.handle(), BINDING));
    assertTrue(store.takeAccepted(issued.handle(), BINDING).isPresent());
    assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
    assertTrue(store.takeAccepted(issued.handle(), BINDING).isEmpty());
  }

  private static byte[] signedProof(String challenge, String identity, KeyPair keyPair) throws Exception {
    Map<String, Object> signed = new LinkedHashMap<>();
    signed.put("profile", WalletLoginProof.PROFILE);
    signed.put("challenge", challenge);
    signed.put("identity_id", identity);
    byte[] bytes = new JsonCanonicalizer(new ObjectMapper().writeValueAsString(signed)).getEncodedUTF8();
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(keyPair.getPrivate());
    signer.update(bytes);
    String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    return ("{\"profile\":\"" + WalletLoginProof.PROFILE + "\",\"challenge\":\"" + challenge
        + "\",\"identity_id\":\"" + identity + "\",\"signature\":\"" + signature + "\"}")
        .getBytes(StandardCharsets.UTF_8);
  }

  private static String transactionKey(String handle) {
    try {
      return "decent-wallet-login-v1:transaction:" + java.util.HexFormat.of().formatHex(
          java.security.MessageDigest.getInstance("SHA-256")
              .digest(handle.getBytes(StandardCharsets.US_ASCII)));
    } catch (java.security.NoSuchAlgorithmException impossible) {
      throw new AssertionError(impossible);
    }
  }
  private static byte[] rawKey(KeyPair pair) {
    byte[] encoded = pair.getPublic().getEncoded();
    return java.util.Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
  }

  private static final class MutableClock extends Clock {
    private java.time.Instant now;
    MutableClock(java.time.Instant now) { this.now = now; }
    void advanceSeconds(long seconds) { now = now.plusSeconds(seconds); }
    @Override public java.time.ZoneOffset getZone() { return java.time.ZoneOffset.UTC; }
    @Override public Clock withZone(java.time.ZoneId zone) { return this; }
    @Override public java.time.Instant instant() { return now; }
  }

  private static final class FailingAcceptedReceiptStore extends MemoryStore {
    @Override public boolean putIfAbsent(String key, long lifespanSeconds) {
      if (key.startsWith("decent-wallet-login-v1:accepted:")) return false;
      return super.putIfAbsent(key, lifespanSeconds);
    }
  }

  private static final class FailingCallbackGateStore extends MemoryStore {
    @Override public boolean replace(String key, Map<String, String> notes) {
      if (key.startsWith("decent-wallet-login-v1:callback:")) return false;
      return super.replace(key, notes);
    }
  }

  private static class MemoryStore implements SingleUseObjectProvider {
    private final Map<String, Map<String, String>> entries = new java.util.concurrent.ConcurrentHashMap<>();
    @Override public void put(String key, long lifespanSeconds, Map<String, String> notes) { entries.put(key, Map.copyOf(notes)); }
    @Override public Map<String, String> get(String key) { return entries.get(key); }
    @Override public Map<String, String> remove(String key) { return entries.remove(key); }
    @Override public boolean replace(String key, Map<String, String> notes) {
      if (!entries.containsKey(key)) return false;
      entries.put(key, Map.copyOf(notes));
      return true;
    }
    @Override public boolean putIfAbsent(String key, long lifespanSeconds) {
      return entries.putIfAbsent(key, Map.of()) == null;
    }
    @Override public boolean contains(String key) { return entries.containsKey(key); }
    @Override public void close() {}
  }
}
