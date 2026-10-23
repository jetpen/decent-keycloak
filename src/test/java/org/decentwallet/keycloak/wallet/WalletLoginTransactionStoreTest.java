package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.keycloak.models.SingleUseObjectProvider;

final class WalletLoginTransactionStoreTest {
  private static final WalletLoginTransactionStore.Binding BINDING = new WalletLoginTransactionStore.Binding(
      "realm-id", "client-id", "root-session-id", "tab-id", "https://site.example/callback", "https://idp.example");

  @Test
  void mapsOnlyExactBuiltInSingleUseProviderImplementations() {
    assertEquals(WalletLoginTransactionStore.SingleUseObjectProviderId.INFINISPAN,
        WalletLoginTransactionStore.providerIdForClassName(
            "org.keycloak.models.sessions.infinispan.InfinispanSingleUseObjectProvider"));
    assertEquals(WalletLoginTransactionStore.SingleUseObjectProviderId.JPA,
        WalletLoginTransactionStore.providerIdForClassName(
            "org.keycloak.singleobject.jpa.JpaSingleUseObjectProvider"));
    assertEquals(WalletLoginTransactionStore.SingleUseObjectProviderId.REMOTE,
        WalletLoginTransactionStore.providerIdForClassName(
            "org.keycloak.models.sessions.infinispan.remote.RemoteInfinispanSingleUseObjectProvider"));
    assertEquals(WalletLoginTransactionStore.SingleUseObjectProviderId.UNKNOWN,
        WalletLoginTransactionStore.providerIdForClassName("example.SecretProvider"));
  }

  @Test
  void issuesBoundChallengeAndLoadsItByOpaqueHandle() {
    var provider = new MemorySingleUseStore();
    var store = new WalletLoginTransactionStore(provider, new SecureRandom(), Clock.systemUTC());

    var issued = store.issue(BINDING);
    var loaded = store.load(issued.handle()).orElseThrow();

    assertEquals(BINDING, loaded.binding());
    assertEquals(issued.challenge(), loaded.challenge());
    assertEquals(issued.csrfToken(), loaded.csrfToken());
    assertEquals(43, issued.handle().length());
    assertEquals(43, issued.challenge().length());
    assertEquals(43, issued.csrfToken().length());
    assertEquals(300, provider.lastPutLifespan.get());
    assertFalse(provider.entries.keySet().iterator().next().contains(issued.handle()));
  }

  @Test
  void onlyMatchingSessionAndChallengeCanConsumePendingTransaction() {
    var store = new WalletLoginTransactionStore(new MemorySingleUseStore(), new SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var wrongBinding = new WalletLoginTransactionStore.Binding(
        "realm-id", "other-client", "root-session-id", "tab-id", "https://site.example/callback", "https://idp.example");

    assertTrue(store.consume(issued.handle(), wrongBinding, issued.challenge(), issued.csrfToken()).isEmpty());
    assertTrue(store.consume(issued.handle(), BINDING, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", issued.csrfToken()).isEmpty());
    assertTrue(store.load(issued.handle()).isPresent());
    assertTrue(store.consume(issued.handle(), BINDING, issued.challenge(), issued.csrfToken()).isPresent());
    assertTrue(store.consume(issued.handle(), BINDING, issued.challenge(), issued.csrfToken()).isEmpty());
  }

  @Test
  void expiresPendingTransactionAndRejectsMalformedHandle() {
    var clock = new MutableClock(Instant.parse("2026-10-12T00:00:00Z"));
    var store = new WalletLoginTransactionStore(new MemorySingleUseStore(), new SecureRandom(), clock);
    var issued = store.issue(BINDING);

    assertTrue(store.load("not-a-handle").isEmpty());
    assertTrue(store.load(issued.handle()).isPresent());
    clock.advanceSeconds(301);
    assertTrue(store.load(issued.handle()).isEmpty());
  }

  @Test
  void acceptedReceiptRetainsCsrfUntilBoundBrowserPollAndExpires() {
    var clock = new MutableClock(Instant.parse("2026-10-12T00:00:00Z"));
    var store = new WalletLoginTransactionStore(new MemorySingleUseStore(), new SecureRandom(), clock);
    var issued = store.issue(BINDING);
    assertTrue(store.consume(issued.handle(), BINDING, issued.challenge(), issued.csrfToken()).isPresent());
    store.markAccepted(issued.handle(), BINDING, "digest", "mailto:alice@example.org", "AA", issued.csrfToken());

    assertTrue(store.acceptedCsrfMatches(issued.handle(), BINDING, issued.csrfToken()));
    assertFalse(store.acceptedCsrfMatches(issued.handle(), BINDING, "wrong"));
    clock.advanceSeconds(301);
    assertFalse(store.acceptedCsrfMatches(issued.handle(), BINDING, issued.csrfToken()));
  }

  @Test
  void limitsFiveInvalidAttemptsForATransactionUntilItsExpiry() {
    var provider = new MemorySingleUseStore();
    var store = new WalletLoginTransactionStore(provider, new SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);

    assertFalse(store.invalidAttemptLimitReached(issued.handle()));
    for (int attempt = 0; attempt < 5; attempt++) {
      assertTrue(store.recordInvalidAttempt(issued.handle()));
    }
    assertTrue(store.invalidAttemptLimitReached(issued.handle()));
    assertFalse(store.recordInvalidAttempt(issued.handle()));
    assertTrue(store.invalidAttemptLimitReached("not-a-handle"));
  }

  @Test
  void identityLookupLeaseAdmitsOnlyOneConcurrentResolverPerTransaction() throws Exception {
    var provider = new MemorySingleUseStore();
    var store = new WalletLoginTransactionStore(provider, new SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    var pool = java.util.concurrent.Executors.newFixedThreadPool(8);
    var ready = new java.util.concurrent.CountDownLatch(8);
    var start = new java.util.concurrent.CountDownLatch(1);
    try {
      var attempts = java.util.stream.IntStream.range(0, 8).mapToObj(index ->
          pool.submit(() -> {
            ready.countDown();
            start.await();
            return store.tryAcquireIdentityLookup(issued.handle());
          })).toList();
      ready.await();
      start.countDown();
      long winners = 0;
      for (var attempt : attempts) if (attempt.get()) winners++;
      assertEquals(1, winners);
      assertFalse(store.tryAcquireIdentityLookup(issued.handle()));
      assertEquals(2, provider.lastPutLifespan.get());
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void identityLookupEmergencyPromotionSurvivesAStaleOwnerReleasingItsWindow() {
    var provider = new MemorySingleUseStore();
    var store = new WalletLoginTransactionStore(provider, new SecureRandom(), Clock.systemUTC());
    var first = store.issue(BINDING);
    var siblingBinding = new WalletLoginTransactionStore.Binding("realm-id", "client-id", "root-session-id",
        "sibling-tab", "https://site.example/callback", "https://idp.example");
    var sibling = store.issue(siblingBinding);

    assertTrue(store.tryAcquireIdentityLookup(first.handle()));
    store.blockIdentityLookups(first.handle(), BINDING);

    assertFalse(store.tryAcquireIdentityLookup(sibling.handle()));
    assertTrue(store.load(sibling.handle()).isPresent());
    assertEquals(300, provider.lifespanForKeyStartingWith("decent-wallet-login-v1:identity-lookup:"));
  }

  @Test
  void onlyOneConcurrentCallbackRedemptionCanConsumeAcceptedGate() throws Exception {
    var provider = new BarrierOnAcceptedReceiptReads();
    var store = new WalletLoginTransactionStore(provider, new SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    assertTrue(store.consume(issued.handle(), BINDING, issued.challenge(), issued.csrfToken()).isPresent());
    store.markAccepted(issued.handle(), BINDING, "proof-digest", "mailto:alice@example.org", "AA", issued.csrfToken());

    var pool = java.util.concurrent.Executors.newFixedThreadPool(2);
    var ready = new java.util.concurrent.CountDownLatch(2);
    var start = new java.util.concurrent.CountDownLatch(1);
    try {
      var attempts = java.util.stream.IntStream.range(0, 2).mapToObj(index -> pool.submit(() -> {
        ready.countDown();
        start.await();
        return store.takeAccepted(issued.handle(), BINDING);
      })).toList();
      assertTrue(ready.await(3, java.util.concurrent.TimeUnit.SECONDS));
      start.countDown();
      long winners = 0;
      for (var attempt : attempts) if (attempt.get(5, java.util.concurrent.TimeUnit.SECONDS).isPresent()) winners++;

      assertEquals(1, winners);
      assertTrue(store.getAccepted(issued.handle(), BINDING).isPresent());
      assertFalse(store.callbackGateAvailable(issued.handle(), BINDING));
      assertTrue(store.takeAccepted(issued.handle(), BINDING).isEmpty());
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void callbackGateIsPublishedBeforeAcceptedStatusBecomesVisible() {
    var provider = new MemorySingleUseStore();
    var store = new WalletLoginTransactionStore(provider, new SecureRandom(), Clock.systemUTC());
    var issued = store.issue(BINDING);
    assertTrue(store.consume(issued.handle(), BINDING, issued.challenge(), issued.csrfToken()).isPresent());

    store.markAccepted(issued.handle(), BINDING, "digest", "mailto:alice@example.org", "AA", issued.csrfToken());

    int callbackIndex = firstKeyWithPrefix(provider.putIfAbsentKeys, "decent-wallet-login-v1:callback:");
    int acceptedIndex = firstKeyWithPrefix(provider.putIfAbsentKeys, "decent-wallet-login-v1:accepted:");
    assertTrue(callbackIndex >= 0 && callbackIndex < acceptedIndex);
    assertTrue(store.peekAccepted(issued.handle()).isPresent());
  }

  private static int firstKeyWithPrefix(java.util.List<String> keys, String prefix) {
    for (int i = 0; i < keys.size(); i++) if (keys.get(i).startsWith(prefix)) return i;
    return -1;
  }

  @Test
  void browserClientLockBlocksNewTransactionsWithoutRevokingExistingSiblings() {
    var store = new WalletLoginTransactionStore(new MemorySingleUseStore(), new SecureRandom(), Clock.systemUTC());
    var first = store.issue(BINDING);
    var siblingBinding = new WalletLoginTransactionStore.Binding("realm-id", "client-id",
        "root-session-id", "another-tab", "https://site.example/callback", "https://idp.example");
    var sibling = store.issue(siblingBinding);
    for (int attempt = 0; attempt < 5; attempt++) {
      assertTrue(store.recordInvalidAttempt(first.handle()));
    }

    var anotherTab = new WalletLoginTransactionStore.Binding("realm-id", "client-id",
        "root-session-id", "third-tab", "https://site.example/callback", "https://idp.example");
    assertThrows(IllegalStateException.class, () -> store.issue(anotherTab));
    assertTrue(store.invalidAttemptLimitReached(first.handle()));
    assertTrue(store.load(sibling.handle()).isPresent());
    assertTrue(store.consume(sibling.handle(), siblingBinding, sibling.challenge(), sibling.csrfToken()).isPresent());
    var otherClient = new WalletLoginTransactionStore.Binding("realm-id", "other-client",
        "root-session-id", "third-tab", "https://site.example/callback", "https://idp.example");
    assertNotNull(store.issue(otherClient));
  }

  @Test
  void rejectsNonHttpsOrNonOriginBindingBeforeWritingState() {
    var provider = new MemorySingleUseStore();
    var store = new WalletLoginTransactionStore(provider, new SecureRandom(), Clock.systemUTC());
    var httpBinding = new WalletLoginTransactionStore.Binding(
        "realm-id", "client-id", "root-session-id", "tab-id", "https://site.example/callback", "http://idp.example");

    assertThrows(IllegalArgumentException.class, () -> store.issue(httpBinding));
    assertTrue(provider.entries.isEmpty());
  }

  private static final class BarrierOnAcceptedReceiptReads extends MemorySingleUseStore {
    private final java.util.concurrent.CountDownLatch readers = new java.util.concurrent.CountDownLatch(2);

    @Override public Map<String, String> get(String key) {
      Map<String, String> value = super.get(key);
      if (key.startsWith("decent-wallet-login-v1:accepted:")) {
        readers.countDown();
        try {
          if (!readers.await(3, java.util.concurrent.TimeUnit.SECONDS)) {
            throw new IllegalStateException("callback redemption did not have two receipt readers");
          }
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
          throw new IllegalStateException("interrupted while synchronizing callback redemptions", interrupted);
        }
      }
      return value;
    }
  }

  private static class MemorySingleUseStore implements SingleUseObjectProvider {
    private final Map<String, Map<String, String>> entries = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.List<String> putIfAbsentKeys = new java.util.concurrent.CopyOnWriteArrayList<>();
    private final java.util.concurrent.ConcurrentHashMap<String, Long> lifespans = new java.util.concurrent.ConcurrentHashMap<>();
    private final AtomicLong lastPutLifespan = new AtomicLong();

    long lifespanForKeyStartingWith(String prefix) {
      return lifespans.entrySet().stream().filter(entry -> entry.getKey().startsWith(prefix))
          .map(Map.Entry::getValue).findFirst().orElse(-1L);
    }

    @Override public void put(String key, long lifespanSeconds, Map<String, String> notes) {
      lastPutLifespan.set(lifespanSeconds);
      lifespans.put(key, lifespanSeconds);
      entries.put(key, new HashMap<>(notes));
    }
    @Override public Map<String, String> get(String key) {
      Map<String, String> value = entries.get(key);
      return value == null ? null : new HashMap<>(value);
    }
    @Override public Map<String, String> remove(String key) {
      Map<String, String> value = entries.remove(key);
      return value == null ? null : new HashMap<>(value);
    }
    @Override public boolean replace(String key, Map<String, String> notes) {
      if (!entries.containsKey(key)) return false;
      entries.put(key, new HashMap<>(notes));
      return true;
    }
    @Override public boolean putIfAbsent(String key, long lifespanSeconds) {
      lastPutLifespan.set(lifespanSeconds);
      putIfAbsentKeys.add(key);
      lifespans.putIfAbsent(key, lifespanSeconds);
      return entries.putIfAbsent(key, new HashMap<>()) == null;
    }
    @Override public boolean contains(String key) { return entries.containsKey(key); }
    @Override public void close() {}
  }

  private static final class MutableClock extends Clock {
    private Instant now;
    MutableClock(Instant now) { this.now = now; }
    void advanceSeconds(long seconds) { now = now.plusSeconds(seconds); }
    @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
    @Override public Clock withZone(java.time.ZoneId zone) { return this; }
    @Override public Instant instant() { return now; }
  }
}
