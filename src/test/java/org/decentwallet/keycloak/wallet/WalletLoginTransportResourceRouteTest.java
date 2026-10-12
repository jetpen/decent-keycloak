package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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
