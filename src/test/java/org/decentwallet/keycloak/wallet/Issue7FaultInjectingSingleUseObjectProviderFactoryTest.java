package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

final class Issue7FaultInjectingSingleUseObjectProviderFactoryTest {
  @TempDir Path directory;
  private static final String HANDLE_DIGEST = handleDigest("exact-key");
  private static final String TRANSACTION = "decent-wallet-login-v1:transaction:" + HANDLE_DIGEST;
  private static final String ACCEPTED = "decent-wallet-login-v1:accepted:" + HANDLE_DIGEST;

  private static String handleDigest(String handle) {
    try {
      return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
          .digest(handle.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    } catch (java.security.NoSuchAlgorithmException impossible) {
      throw new AssertionError(impossible);
    }
  }

  @Test void consumeLossCommitsExactRemovalThenThrowsOnlyOnceAcrossFactoryRecreation() {
    var delegate = new Memory();
    var provider = factory("consume-loss").create(session(delegate));
    provider.put(TRANSACTION, 300, Map.of("status", "pending"));
    provider.put("unrelated", 300, Map.of("status", "untouched"));
    assertThrows(IllegalStateException.class, () -> provider.remove(TRANSACTION));
    assertNull(delegate.get(TRANSACTION));
    assertEquals("untouched", delegate.get("unrelated").get("status"));
    provider.put(TRANSACTION, 300, Map.of("status", "fresh"));
    assertEquals("fresh", factory("consume-loss").create(session(delegate)).remove(TRANSACTION).get("status"));
    assertNull(provider.remove(TRANSACTION));
  }

  @Test void acceptedPostwriteThrowsAfterCommitAndThenDelegatesFreshOperations() {
    var delegate = new Memory();
    var provider = factory("accepted-receipt-write").create(session(delegate));
    provider.put(ACCEPTED, 300, Map.of());
    assertThrows(IllegalStateException.class,
        () -> provider.replace(ACCEPTED, Map.of("status", "accepted")));
    assertEquals("accepted", delegate.get(ACCEPTED).get("status"));
    assertTrue(provider.replace(ACCEPTED, Map.of("status", "accepted")));
    assertNotNull(provider.remove(ACCEPTED));
    provider.close();
    assertFalse(delegate.closed, "session owns the delegate lifecycle");
  }

  @Test void acceptedPrecommitRejectionLeavesReservationUnchangedThenRecovers() {
    var delegate = new Memory();
    var provider = factory("accepted-receipt-write-false").create(session(delegate));
    assertTrue(provider.putIfAbsent(ACCEPTED, 300));
    assertFalse(provider.replace(ACCEPTED, Map.of("status", "accepted")));
    assertEquals(Map.of(), delegate.get(ACCEPTED));
    assertTrue(provider.replace(ACCEPTED, Map.of("status", "accepted")));
    assertTrue(provider.contains(ACCEPTED));
  }

  @Test void unsupportedModesAndMissingDelegateFailClosed() {
    assertThrows(IllegalArgumentException.class, () -> factory("concurrent-consume"));
    assertThrows(IllegalStateException.class, () -> factory("consume-loss").create(session(null)));
  }

  @Test void storeOperationAndFaultMarkersCarryWrapperOperationAndHandleCorrelation() {
    String expected = WalletLoginTransportHandler.requestCorrelationId("exact-key");
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    PrintStream original = System.err;
    try (PrintStream replacement = new PrintStream(captured)) {
      System.setErr(replacement);
      var delegate = new Memory();
      var consume = factory("consume-loss").create(session(delegate));
      consume.put(TRANSACTION, 300, Map.of("status", "pending"));
      assertThrows(IllegalStateException.class, () -> consume.remove(TRANSACTION));

      var accepted = new Memory();
      var write = new Issue7FaultInjectingSingleUseObjectProviderFactory(
          "accepted-receipt-write", directory.resolve("accepted-marker"))
          .create(session(accepted));
      write.put(ACCEPTED, 300, Map.of());
      assertThrows(IllegalStateException.class,
          () -> write.replace(ACCEPTED, Map.of("status", "accepted")));

      var rejected = new Issue7FaultInjectingSingleUseObjectProviderFactory(
          "accepted-receipt-write-false", directory.resolve("false-marker"))
          .create(session(new Memory()));
      rejected.put(ACCEPTED, 300, Map.of());
      assertFalse(rejected.replace(ACCEPTED, Map.of("status", "accepted")));
    } finally {
      System.setErr(original);
    }
    String logs = captured.toString(java.nio.charset.StandardCharsets.UTF_8);
    for (String operation : new String[] {"transaction_remove", "accepted_replace"}) {
      String exactMarker = "provider=issue7-fault-injection operation=" + operation + " request=" + expected;
      assertTrue(logs.contains("ISSUE7_TEST_PROVIDER_OPERATION: " + exactMarker));
      assertTrue(logs.contains("ISSUE7_TEST_FAULT: " + exactMarker.substring(0,
          exactMarker.length() - (" request=" + expected).length())));
    }
    assertTrue(logs.contains("pending consume committed then threw request=" + expected));
    assertTrue(logs.contains("accepted receipt write committed then threw request=" + expected));
    assertTrue(logs.contains("accepted receipt write returned false before commit request=" + expected));
  }

  @Test void markersCorrelateToHandleThroughRealTransactionStoreKeys() {
    var binding = new WalletLoginTransactionStore.Binding("realm", "client", "root", "tab",
        "https://site.example/callback", "https://idp.example");
    for (String mode : new String[] {"consume-loss", "accepted-receipt-write", "accepted-receipt-write-false"}) {
      var captured = new ByteArrayOutputStream();
      var original = System.err;
      String requestId;
      try (var replacement = new PrintStream(captured)) {
        System.setErr(replacement);
        var delegate = new Memory();
        var provider = new Issue7FaultInjectingSingleUseObjectProviderFactory(mode,
            directory.resolve(mode + "-real-key")).create(session(delegate));
        var store = new WalletLoginTransactionStore(provider, new java.security.SecureRandom(),
            java.time.Clock.systemUTC());
        var issued = store.issue(binding, WalletLoginTransactionStore.Intent.SIGNUP);
        requestId = WalletLoginTransportHandler.requestCorrelationId(issued.handle());
        if (mode.equals("consume-loss")) {
          assertThrows(IllegalStateException.class, () -> store.consume(issued.handle(), binding,
              issued.challenge(), issued.csrfToken()));
          assertTrue(store.load(issued.handle()).isEmpty());
        } else {
          assertTrue(store.consume(issued.handle(), binding, issued.challenge(), issued.csrfToken()).isPresent());
          assertThrows(IllegalStateException.class, () -> store.markAccepted(issued.handle(), binding,
              "proof-digest", "identity", "public-key", issued.csrfToken(),
              WalletLoginTransactionStore.Intent.SIGNUP));
        }
      } finally {
        System.setErr(original);
      }
      String operation = mode.equals("consume-loss") ? "transaction_remove" : "accepted_replace";
      String logs = captured.toString(java.nio.charset.StandardCharsets.UTF_8);
      assertTrue(logs.contains("ISSUE7_TEST_PROVIDER_OPERATION: provider=issue7-fault-injection operation="
          + operation + " request=" + requestId), "real storage-key marker must correlate for " + mode);
      String outcome = mode.equals("consume-loss") ? "pending consume committed then threw"
          : mode.equals("accepted-receipt-write") ? "accepted receipt write committed then threw"
          : "accepted receipt write returned false before commit";
      assertTrue(logs.contains("ISSUE7_TEST_FAULT: provider=issue7-fault-injection operation="
          + operation + " " + outcome + " request=" + requestId), "fault must use the handle correlation");
    }
  }

  private Issue7FaultInjectingSingleUseObjectProviderFactory factory(String mode) {
    return new Issue7FaultInjectingSingleUseObjectProviderFactory(mode, directory.resolve("fault-marker"));
  }

  private KeycloakSession session(SingleUseObjectProvider provider) {
    return (KeycloakSession) Proxy.newProxyInstance(getClass().getClassLoader(),
        new Class<?>[] {KeycloakSession.class}, (proxy, method, args) -> {
          if (method.getName().equals("getProvider")) {
            assertEquals(SingleUseObjectProvider.class, args[0]);
            assertEquals("infinispan", args[1]);
            return provider;
          }
          throw new UnsupportedOperationException(method.getName());
        });
  }

  private static final class Memory implements SingleUseObjectProvider {
    final Map<String, Map<String, String>> entries = new HashMap<>();
    boolean closed;
    @Override public void put(String key, long lifespan, Map<String, String> notes) { entries.put(key, notes); }
    @Override public Map<String, String> get(String key) { return entries.get(key); }
    @Override public Map<String, String> remove(String key) { return entries.remove(key); }
    @Override public boolean replace(String key, Map<String, String> notes) {
      if (!entries.containsKey(key)) return false;
      entries.put(key, notes);
      return true;
    }
    @Override public boolean putIfAbsent(String key, long lifespan) { return entries.putIfAbsent(key, Map.of()) == null; }
    @Override public boolean contains(String key) { return entries.containsKey(key); }
    @Override public void close() { closed = true; }
  }
}
