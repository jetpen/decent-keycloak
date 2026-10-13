package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import java.lang.reflect.Method;
import java.util.Map;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.junit.jupiter.api.Test;

class WalletLoginTransportResourceRouteTest {
  private static final String IDP_ORIGIN = "https://idp.example";
  private static final String WALLET_ORIGIN = "https://wallet.example";
  private static final WalletLoginTransactionStore.Binding BINDING = new WalletLoginTransactionStore.Binding(
      "realm-id", "client-id", "root-session-id", "tab-id", "https://site.example/callback", IDP_ORIGIN);

  @Test
  void registersDeterministicProbeAndTransactionRoutesAtRealmExtensionRoot() {
    assertNull(WalletLoginTransportResource.class.getAnnotation(Path.class),
        "realm extension is a subresource locator; map routes on its methods");
    assertPath("routeProbe", "v1/transactions/health");
    assertPath("transactionGet", "v1/transactions/{handle}");
    assertPath("transactionPost", "v1/transactions/{handle}");
    assertPath("status", "v1/transactions/{handle}/status");
  }

  @Test
  void proofRouteStreamsTheRequestBodyInsteadOfBufferingAnUnboundedByteArray() {
    Method method = java.util.Arrays.stream(WalletLoginTransportResource.class.getDeclaredMethods())
        .filter(candidate -> candidate.getName().equals("transactionPost")).findFirst().orElseThrow();
    assertEquals(java.io.InputStream.class,
        method.getParameterTypes()[method.getParameterCount() - 1]);
  }

  @Test
  void requiresOneChallengeGetRouteAndOneProofPostOnTheQrLocatorPath() {
    assertEquals(1, countRoutes(jakarta.ws.rs.GET.class, "v1/transactions/{handle}"));
    assertEquals(1, countRoutes(jakarta.ws.rs.POST.class, "v1/transactions/{handle}"));
    assertEquals(1, countRoutes(jakarta.ws.rs.GET.class, "v1/transactions/{handle}/status"));
    assertEquals(1, countRoutes(jakarta.ws.rs.OPTIONS.class, "v1/transactions/{handle}"));
  }

  private static long countRoutes(Class<? extends java.lang.annotation.Annotation> verb, String path) {
    return java.util.Arrays.stream(WalletLoginTransportResource.class.getDeclaredMethods())
        .filter(method -> method.isAnnotationPresent(verb))
        .filter(method -> method.getAnnotation(Path.class) != null)
        .filter(method -> path.equals(method.getAnnotation(Path.class).value()))
        .count();
  }

  @Test
  void sharesWalletChallengeAndCsrfHeadersWithPostButNotTheUnrelatedGet() {
    var resource = new WalletLoginTransportResource();
    var handler = org.mockito.Mockito.mock(WalletLoginTransportHandler.class);
    org.mockito.Mockito.when(handler.allowsWalletOrigin(WALLET_ORIGIN)).thenReturn(true);
    var store = new WalletLoginTransactionStore(new MemoryStore(), new java.security.SecureRandom(),
        java.time.Clock.systemUTC());
    var issued = store.issue(BINDING);
    org.mockito.Mockito.when(handler.getChallenge(issued.handle(), WALLET_ORIGIN, "cross-site", "cors", "empty", IDP_ORIGIN))
        .thenReturn(WalletLoginTransportHandler.HttpResult.json(200, Map.of("profile", WalletLoginProof.PROFILE,
            "challenge", issued.challenge(), "csrf_token", issued.csrfToken())));
    org.mockito.Mockito.when(handler.submitProof(org.mockito.ArgumentMatchers.eq(issued.handle()),
        org.mockito.ArgumentMatchers.eq(WALLET_ORIGIN), org.mockito.ArgumentMatchers.eq("cross-site"),
        org.mockito.ArgumentMatchers.eq("cors"), org.mockito.ArgumentMatchers.eq("empty"),
        org.mockito.ArgumentMatchers.eq("application/json"), org.mockito.ArgumentMatchers.eq(issued.csrfToken()),
        org.mockito.ArgumentMatchers.any(byte[].class), org.mockito.ArgumentMatchers.eq(IDP_ORIGIN)))
        .thenReturn(WalletLoginTransportHandler.HttpResult.empty(403));
    setField(resource, "handler", handler);
    setField(resource, "idpOrigin", IDP_ORIGIN);
    setField(resource, "walletOrigin", WALLET_ORIGIN);

    var responseType = org.mockito.Mockito.mockStatic(jakarta.ws.rs.core.Response.class);
    var builder = org.mockito.Mockito.mock(jakarta.ws.rs.core.Response.ResponseBuilder.class);
    responseType.when(() -> jakarta.ws.rs.core.Response.status(org.mockito.ArgumentMatchers.anyInt()))
        .thenReturn(builder);
    responseType.when(() -> jakarta.ws.rs.core.Response.fromResponse(org.mockito.ArgumentMatchers.any()))
        .thenReturn(builder);
    org.mockito.Mockito.when(builder.header(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any()))
        .thenReturn(builder);
    org.mockito.Mockito.when(builder.build()).thenReturn(org.mockito.Mockito.mock(Response.class));
    try (responseType) {
      Response get = resource.transactionGet(issued.handle(), WALLET_ORIGIN, "cross-site", "cors", "empty");
      Response post = resource.transactionPost(issued.handle(), WALLET_ORIGIN, "cross-site", "cors", "empty",
          "application/json", issued.csrfToken(), new java.io.ByteArrayInputStream(new byte[] {1}));

      assertNotNull(get);
      assertNotNull(post);
      org.mockito.Mockito.verify(handler).getChallenge(issued.handle(), WALLET_ORIGIN, "cross-site", "cors", "empty", IDP_ORIGIN);
      org.mockito.Mockito.verify(handler).submitProof(org.mockito.ArgumentMatchers.eq(issued.handle()),
          org.mockito.ArgumentMatchers.eq(WALLET_ORIGIN), org.mockito.ArgumentMatchers.eq("cross-site"),
          org.mockito.ArgumentMatchers.eq("cors"), org.mockito.ArgumentMatchers.eq("empty"),
          org.mockito.ArgumentMatchers.eq("application/json"), org.mockito.ArgumentMatchers.eq(issued.csrfToken()),
          org.mockito.ArgumentMatchers.any(byte[].class), org.mockito.ArgumentMatchers.eq(IDP_ORIGIN));
    }
  }

  private static void setField(Object target, String fieldName, Object value) {
    try {
      var field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }

  private static final class MemoryStore implements org.keycloak.models.SingleUseObjectProvider {
    private final java.util.Map<String, java.util.Map<String, String>> values =
        new java.util.concurrent.ConcurrentHashMap<>();
    @Override public void put(String key, long lifespanSeconds, java.util.Map<String, String> notes) {
      values.put(key, java.util.Map.copyOf(notes));
    }
    @Override public java.util.Map<String, String> get(String key) { return values.get(key); }
    @Override public java.util.Map<String, String> remove(String key) { return values.remove(key); }
    @Override public boolean replace(String key, java.util.Map<String, String> notes) {
      if (!values.containsKey(key)) return false;
      values.put(key, java.util.Map.copyOf(notes));
      return true;
    }
    @Override public boolean putIfAbsent(String key, long lifespanSeconds) {
      return values.putIfAbsent(key, java.util.Map.of()) == null;
    }
    @Override public boolean contains(String key) { return values.containsKey(key); }
    @Override public void close() { }
  }

  @Test
  void proofBodyReaderStopsAtTheConfiguredLimitPlusOneByte() throws Exception {
    final int sourceLength = WalletLoginTransportHandler.MAX_PROOF_BYTES + 1000;
    var stream = new java.io.InputStream() {
      private int readCount;
      @Override public int read() {
        if (readCount >= sourceLength) return -1;
        readCount++;
        return 'x';
      }
      @Override public int read(byte[] buffer, int offset, int length) {
        if (readCount >= sourceLength) return -1;
        int count = Math.min(length, sourceLength - readCount);
        java.util.Arrays.fill(buffer, offset, offset + count, (byte) 'x');
        readCount += count;
        return count;
      }
      int readCount() { return readCount; }
    };

    assertNull(WalletLoginTransportResource.readBoundedBody(stream));
    assertEquals(WalletLoginTransportHandler.MAX_PROOF_BYTES + 1, stream.readCount());
  }

  @Test
  void walletAndStatusRoutesCaptureCompleteFetchMetadata() {
    for (String methodName : java.util.List.of("transactionGet", "transactionPost", "status", "preflight")) {
      assertTrue(hasHeaderParameter(methodName, "Sec-Fetch-Site"));
      assertTrue(hasHeaderParameter(methodName, "Sec-Fetch-Mode"));
      assertTrue(hasHeaderParameter(methodName, "Sec-Fetch-Dest"));
    }
  }

  private static boolean hasHeaderParameter(String methodName, String name) {
    Method method = java.util.Arrays.stream(WalletLoginTransportResource.class.getDeclaredMethods())
        .filter(candidate -> candidate.getName().equals(methodName)).findFirst().orElseThrow();
    return java.util.Arrays.stream(method.getParameters()).anyMatch(parameter -> {
      var annotation = parameter.getAnnotation(jakarta.ws.rs.HeaderParam.class);
      return annotation != null && name.equals(annotation.value());
    });
  }

  @Test
  void fetchMetadataRequiresCorsAndEmptyDestinationForBrowserTransport() {
    assertTrue(WalletLoginTransportResource.validFetchMetadata("cross-site", "cors", "empty"));
    assertFalse(WalletLoginTransportResource.validFetchMetadata("cross-site", "navigate", "document"));
    assertFalse(WalletLoginTransportResource.validFetchMetadata("cross-site", "cors", "document"));
    assertFalse(WalletLoginTransportResource.validFetchMetadata(null, "cors", "empty"));
    assertTrue(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "POST", "content-type,x-decent-csrf", "cross-site", "cors", "empty"));
    assertFalse(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "POST", "content-type,x-decent-csrf", null, "cors", "empty"));
  }

  @Test
  void challengeGetPreflightAllowsSafelistedNoHeaderSetAndAccept() {
    assertTrue(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "GET", ""));
    assertTrue(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "GET", "accept"));
  }

  @Test
  void challengeGetPreflightRejectsNonSafelistedHeaders() {
    assertFalse(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "GET", "accept,authorization"));
  }

  @Test
  void challengeGetPreflightRejectsUnnecessaryCsrfAndNonSafelistedHeaders() {
    assertFalse(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "GET", "x-decent-csrf"));
    assertFalse(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "GET", "accept,authorization"));
  }

  @Test
  void proofPostPreflightRequiresCsrfAndJsonHeaders() {
    assertTrue(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "POST", "content-type,x-decent-csrf"));
    assertFalse(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "POST", "content-type"));
    assertFalse(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "POST", "content-type,x-decent-csrf,authorization"));
  }

  @Test
  void preflightResponseAdvertisesOnlyTheRequestedSupportedHeaders() {
    assertEquals("", WalletLoginTransportResource.allowedPreflightHeaders("GET", ""));
    assertEquals("Accept", WalletLoginTransportResource.allowedPreflightHeaders("GET", "accept"));
    assertEquals("Content-Type, X-Decent-CSRF",
        WalletLoginTransportResource.allowedPreflightHeaders("POST", "content-type,x-decent-csrf"));
  }

  @Test
  void preflightRejectsUntrustedOriginsAndMethods() {
    assertFalse(WalletLoginTransportResource.validPreflightRequest("https://attacker.example", false,
        "POST", "content-type,x-decent-csrf"));
    assertFalse(WalletLoginTransportResource.validPreflightRequest("https://wallet.example", true,
        "PUT", "content-type,x-decent-csrf"));
  }

  private static void assertPath(String methodName, String expected) {
    Method method = java.util.Arrays.stream(WalletLoginTransportResource.class.getDeclaredMethods())
        .filter(candidate -> candidate.getName().equals(methodName))
        .filter(candidate -> candidate.isAnnotationPresent(GET.class)
            || candidate.isAnnotationPresent(jakarta.ws.rs.POST.class))
        .findFirst().orElseThrow();
    assertEquals(expected, method.getAnnotation(Path.class).value());
  }
}
