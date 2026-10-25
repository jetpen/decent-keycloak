package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

final class Issue7FaultInjectingSingleUseObjectProviderFactoryTest {
  @TempDir Path directory;
  private static final String TRANSACTION = "decent-wallet-login-v1:transaction:exact-key";
  private static final String ACCEPTED = "decent-wallet-login-v1:accepted:exact-key";

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
