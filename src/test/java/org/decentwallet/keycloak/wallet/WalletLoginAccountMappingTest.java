package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;

final class WalletLoginAccountMappingTest {
  @Test
  void authenticationIntentIsBoundToPendingTransactionNotClientSuppliedProof() {
    boolean implemented = java.util.Arrays.stream(WalletLoginTransactionStore.class.getDeclaredMethods())
        .anyMatch(method -> method.getName().equals("issue")
            && java.util.Arrays.asList(method.getParameterTypes()).contains(WalletLoginTransactionStore.Intent.class));
    org.junit.jupiter.api.Assertions.assertTrue(implemented,
        "signup intent must be carried by the server-bound transaction binding");
  }

  @Test
  void supportsSignupProvisioningThroughASeparateEnsureUserPath() {
    boolean implemented = java.util.Arrays.stream(WalletLoginAccountMapping.class.getDeclaredMethods())
        .anyMatch(method -> method.getName().equals("ensureEnabledUser")
            && java.util.Arrays.asList(method.getParameterTypes()).contains(boolean.class));
    org.junit.jupiter.api.Assertions.assertTrue(implemented,
        "signup intent needs an exact-mapping-or-provision path before nonce consumption");
  }

  @Test
  void signupProvisioningSetsProfileFieldsRequiredByKeycloakProfileBeforeConsumption() {
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var created = mock(UserModel.class);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, "mailto:new@example.org"))
        .thenReturn(Stream.<UserModel>empty(), Stream.of(created));
    when(users.addUser(realm, null,
        "wallet-" + hexDigest("mailto:new@example.org"), true, true)).thenReturn(created);
    when(created.getId()).thenReturn("user-id");
    when(created.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn("mailto:new@example.org");
    when(created.isEnabled()).thenReturn(true);

    assertEquals(created, WalletLoginAccountMapping.ensureEnabledUser(users, realm,
        "mailto:new@example.org", true));

    verify(created).setEmail("wallet-" + hexDigest("mailto:new@example.org").substring(0, 32) + "@example.com");
    verify(created).setFirstName("Wallet");
    verify(created).setLastName("Account");
  }

  @Test
  void signupProvisioningDoesNotTreatStoreFailureWithNoWinnerAsPolicyDenial() {
    String identityId = "mailto:no-winner-after-create-failure@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    when(users.addUser(realm, null, "wallet-" + hexDigest(identityId), true, true))
        .thenThrow(new IllegalStateException("temporary user-store failure"));
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(Stream.empty()).thenThrow(new IllegalStateException("lookup transport unavailable"));

    var thrown = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));

    org.junit.jupiter.api.Assertions.assertEquals("identity mapping read-back unavailable", thrown.getMessage());
    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).removeUser(org.mockito.ArgumentMatchers.eq(realm),
        org.mockito.ArgumentMatchers.any(UserModel.class));
  }

  @Test
  void signupProvisioningReturnsUnavailableOnIdentityStoreFailureWhenNoExactWinnerExists() {
    String identityId = "mailto:temporary-database-failure@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var readbackFailure = new IllegalStateException("identity mapping read-back unavailable");
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(Stream.empty()).thenThrow(readbackFailure);
    String username = "wallet-" + hexDigest(identityId);
    when(users.addUser(realm, null, username, true, true))
        .thenThrow(new IllegalStateException("concurrent username insert won"));

    var thrown = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));
    org.junit.jupiter.api.Assertions.assertEquals("identity mapping read-back unavailable", thrown.getMessage());
    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).removeUser(org.mockito.ArgumentMatchers.eq(realm),
        org.mockito.ArgumentMatchers.any(UserModel.class));
  }

  @Test
  void signupProvisioningDoesNotDeleteCreatedUserWhenMappingReadBackFails() {
    String identityId = "mailto:created-but-unreadable@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var created = mock(UserModel.class);
    when(created.getId()).thenReturn("created-id");
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(Stream.empty()).thenThrow(new IllegalStateException("read-back outage"));
    when(users.addUser(realm, null, "wallet-" + hexDigest(identityId), true, true)).thenReturn(created);

    var thrown = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));

    org.junit.jupiter.api.Assertions.assertEquals("identity mapping read-back unavailable", thrown.getMessage());
    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).removeUser(realm, created);
  }

  @Test
  void signupProvisioningTreatsMissingPostCreateMappingAsUnavailableNotPolicyDenial() {
    String identityId = "mailto:created-without-mapping@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var created = mock(UserModel.class);
    when(created.getId()).thenReturn("created-id");
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(Stream.empty(), Stream.empty());
    when(users.addUser(realm, null, "wallet-" + hexDigest(identityId), true, true)).thenReturn(created);
    when(created.isEnabled()).thenReturn(true);
    when(created.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);

    var thrown = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));

    org.junit.jupiter.api.Assertions.assertEquals("identity mapping read-back unavailable", thrown.getMessage());
    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).removeUser(realm, created);
  }

  @Test
  void signupProvisioningFailsClosedWhenPostCreateReadbackExceedsCandidateBound() {
    String identityId = "mailto:created-over-cap@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var created = mock(UserModel.class);
    // Synthetic provider rows exercise the 65-result bound; none are persisted users.
    var postCreateCandidates = new java.util.ArrayList<UserModel>();
    for (int i = 0; i < 64; i++) {
      var unrelated = mock(UserModel.class);
      when(unrelated.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE))
          .thenReturn("mailto:other-" + i + "@example.org");
      postCreateCandidates.add(unrelated);
    }
    postCreateCandidates.add(created);
    when(created.getId()).thenReturn("created-id");
    when(created.isEnabled()).thenReturn(true);
    when(created.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(Stream.empty(), postCreateCandidates.stream());
    when(users.addUser(realm, null, "wallet-" + hexDigest(identityId), true, true)).thenReturn(created);

    var thrown = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));

    org.junit.jupiter.api.Assertions.assertEquals("identity mapping read-back unavailable", thrown.getMessage());
    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).removeUser(realm, created);
  }

  @Test
  void signupProvisioningFailsClosedWhenConcurrentCreateReadbackExceedsCandidateBound() {
    String identityId = "mailto:concurrent-over-cap@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var winner = mock(UserModel.class);
    // Synthetic provider rows exercise the conflict-path bound; none are persisted users.
    var conflictCandidates = new java.util.ArrayList<UserModel>();
    for (int i = 0; i < 64; i++) {
      var unrelated = mock(UserModel.class);
      when(unrelated.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE))
          .thenReturn("mailto:other-conflict-" + i + "@example.org");
      conflictCandidates.add(unrelated);
    }
    conflictCandidates.add(winner);
    when(winner.getId()).thenReturn("concurrent-winner-id");
    when(winner.isEnabled()).thenReturn(true);
    when(winner.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(Stream.empty(), conflictCandidates.stream());
    when(users.addUser(realm, null, "wallet-" + hexDigest(identityId), true, true))
        .thenThrow(new IllegalStateException("unique username conflict"));

    var thrown = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));

    org.junit.jupiter.api.Assertions.assertEquals("identity mapping read-back unavailable", thrown.getMessage());
    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).removeUser(realm, winner);
  }

  @Test
  void collisionRecheckCandidateCapReturnsUnavailableWithoutDeletingWinner() {
    String identityId = "mailto:collision-cap@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var winner = mock(UserModel.class);
    when(winner.isEnabled()).thenReturn(true);
    when(winner.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    var consumed = new java.util.concurrent.atomic.AtomicInteger();
    var mismatches = java.util.stream.IntStream.range(0, 65).mapToObj(index -> {
      var user = mock(UserModel.class);
      when(user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE))
          .thenReturn("mailto:collision-mismatch-" + index + "@example.org");
      return user;
    }).toList();
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(Stream.empty(), Stream.concat(Stream.of(winner), mismatches.stream())
            .peek(user -> consumed.incrementAndGet()));
    String username = "wallet-" + hexDigest(identityId);
    when(users.addUser(realm, null, username, true, true))
        .thenThrow(new IllegalStateException("concurrent username insert won"));

    var thrown = org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));

    org.junit.jupiter.api.Assertions.assertEquals("identity mapping read-back unavailable", thrown.getMessage());
    assertEquals(65, consumed.get());
    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).removeUser(realm, winner);
  }

  private static String hexDigest(String identityId) {
    try {
      return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
          .digest(identityId.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
  }
  // Local, single-process application characterization only; this is not provider or cross-node evidence.
  @Test
  void localSingleProcessSignupFailsClosedUntilWinningAccountReceivesItsProductionIdentityMapping()
      throws Exception {
    String identityId = "mailto:local-race@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var bothInitialLookups = new CountDownLatch(2);
    var losingReadbackStarted = new CountDownLatch(1);
    var winnerMayWriteIdentity = new CountDownLatch(1);
    var searchCount = new AtomicInteger();
    var addCount = new AtomicInteger();
    var successfulAdds = new AtomicInteger();
    var deletedAccounts = new AtomicInteger();
    var persistedIdentity = new AtomicReference<String>();
    var persistedEnabled = new java.util.concurrent.atomic.AtomicBoolean(false);
    var winner = mock(UserModel.class);
    when(winner.getId()).thenReturn("local-race-winner");
    when(winner.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE))
        .thenAnswer(ignored -> persistedIdentity.get());
    when(winner.isEnabled()).thenAnswer(ignored -> persistedEnabled.get());
    org.mockito.Mockito.doAnswer(invocation -> {
      assertEquals(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, invocation.getArgument(0));
      assertEquals(identityId, invocation.getArgument(1));
      assertEquals(true, winnerMayWriteIdentity.await(5, TimeUnit.SECONDS),
          "winner identity write must be released after losing exact-ID readback");
      persistedIdentity.set(invocation.getArgument(1));
      return null;
    }).when(winner).setSingleAttribute(org.mockito.ArgumentMatchers.anyString(),
        org.mockito.ArgumentMatchers.anyString());
    org.mockito.Mockito.doAnswer(invocation -> {
      persistedEnabled.set(invocation.getArgument(0));
      return null;
    }).when(winner).setEnabled(org.mockito.ArgumentMatchers.anyBoolean());
    org.mockito.Mockito.doAnswer(invocation -> {
      deletedAccounts.incrementAndGet();
      return true;
    }).when(users).removeUser(org.mockito.ArgumentMatchers.eq(realm),
        org.mockito.ArgumentMatchers.any(UserModel.class));
    org.mockito.Mockito.when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)).thenAnswer(invocation -> {
          int lookup = searchCount.incrementAndGet();
          if (lookup <= 2) {
            bothInitialLookups.countDown();
            assertEquals(true, bothInitialLookups.await(5, TimeUnit.SECONDS),
                "both calls must observe the initial empty exact-identity lookup");
            return Stream.empty();
          }
          if (persistedIdentity.get() == null && lookup == 3) losingReadbackStarted.countDown();
          return persistedIdentity.get() == null ? Stream.empty() : Stream.of(winner);
        });
    org.mockito.Mockito.when(users.addUser(realm, null,
        "wallet-" + hexDigest(identityId), true, true)).thenAnswer(invocation -> {
          if (addCount.incrementAndGet() == 1) {
            successfulAdds.incrementAndGet();
            return winner;
          }
          throw new IllegalStateException("unique username conflict");
        });

    ExecutorService executor = Executors.newFixedThreadPool(2);
    ExecutorCompletionService<UserModel> completions = new ExecutorCompletionService<>(executor);
    try {
      completions.submit(() -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));
      completions.submit(() -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));

      assertEquals(true, losingReadbackStarted.await(5, TimeUnit.SECONDS),
          "conflict loser must perform its independent exact-ID readback");
      var loserCompletion = completions.poll(5, TimeUnit.SECONDS);
      org.junit.jupiter.api.Assertions.assertNotNull(loserCompletion,
          "conflict loser must finish within the bound");
      var loserFailure = org.junit.jupiter.api.Assertions.assertThrows(
          java.util.concurrent.ExecutionException.class, () -> loserCompletion.get(5, TimeUnit.SECONDS));
      org.junit.jupiter.api.Assertions.assertInstanceOf(IllegalStateException.class,
          loserFailure.getCause());
      assertEquals("user provisioning unavailable", loserFailure.getCause().getMessage());
      assertNull(persistedIdentity.get(), "the winner is still inside its production setter");
      winnerMayWriteIdentity.countDown();

      var winnerCompletion = completions.poll(5, TimeUnit.SECONDS);
      org.junit.jupiter.api.Assertions.assertNotNull(winnerCompletion,
          "winning provisioning call must finish within the bound");
      assertEquals(winner, winnerCompletion.get(5, TimeUnit.SECONDS));
      assertEquals(identityId, persistedIdentity.get());
      assertEquals(true, persistedEnabled.get());
      assertEquals(1, successfulAdds.get());
      assertEquals(2, addCount.get());
      assertEquals(0, deletedAccounts.get());

      assertEquals(winner, WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));
      assertEquals(2, addCount.get(), "fresh ensure must reuse the exact enabled winner");
    } finally {
      winnerMayWriteIdentity.countDown();
      executor.shutdownNow();
      assertEquals(true, executor.awaitTermination(5, TimeUnit.SECONDS),
          "race executor must terminate within the bound");
    }
  }

  // Local, single-process application characterization only; it does not qualify a Keycloak provider or cross-node atomicity.
  @Test
  void concurrentSignupProvisioningAdoptsWinnerAfterBothLookupsMissAndWinnerIsConfigured() throws Exception {
    String identityId = "mailto:concurrent-race@example.org";
    String username = "wallet-" + hexDigest(identityId);
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var winner = mock(UserModel.class);
    var winnerIdentity = new java.util.concurrent.atomic.AtomicReference<String>();
    var winnerEnabled = new java.util.concurrent.atomic.AtomicBoolean(false);
    when(winner.getId()).thenReturn("concurrent-winner-id");
    when(winner.isEnabled()).thenAnswer(ignored -> winnerEnabled.get());
    when(winner.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE))
        .thenAnswer(ignored -> winnerIdentity.get());
    var configurationEffects = new java.util.concurrent.atomic.AtomicInteger();
    var winnerConfigured = new java.util.concurrent.CountDownLatch(1);
    org.mockito.Mockito.doAnswer(invocation -> {
      winnerIdentity.set(invocation.getArgument(1));
      if (configurationEffects.incrementAndGet() == 2) winnerConfigured.countDown();
      return null;
    }).when(winner).setSingleAttribute(
        org.mockito.ArgumentMatchers.eq(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE),
        org.mockito.ArgumentMatchers.anyString());
    org.mockito.Mockito.doAnswer(invocation -> {
      winnerEnabled.set(invocation.getArgument(0));
      if (configurationEffects.incrementAndGet() == 2) winnerConfigured.countDown();
      return null;
    }).when(winner).setEnabled(org.mockito.ArgumentMatchers.anyBoolean());

    var accountsByUsername = new java.util.concurrent.ConcurrentHashMap<String, UserModel>();
    var initialSearches = new java.util.concurrent.atomic.AtomicInteger();
    var totalSearches = new java.util.concurrent.atomic.AtomicInteger();
    var createCalls = new java.util.concurrent.atomic.AtomicInteger();
    var successfulCreates = new java.util.concurrent.atomic.AtomicInteger();
    var uniquenessConflicts = new java.util.concurrent.atomic.AtomicInteger();
    var initialLookupBarrier = new java.util.concurrent.CyclicBarrier(2);
    var createBarrier = new java.util.concurrent.CyclicBarrier(2);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)).thenAnswer(invocation -> {
          totalSearches.incrementAndGet();
          if (initialSearches.getAndIncrement() < 2) {
            awaitRaceBarrier(initialLookupBarrier, "both initial exact-identity lookups");
            return Stream.empty();
          }
          return accountsByUsername.values().stream()
              .filter(candidate -> identityId.equals(
                  candidate.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)));
        });
    when(users.addUser(realm, null, username, true, true)).thenAnswer(invocation -> {
      createCalls.incrementAndGet();
      assertEquals(username, invocation.getArgument(2));
      awaitRaceBarrier(createBarrier, "both deterministic-username create attempts");
      if (accountsByUsername.putIfAbsent(username, winner) == null) {
        successfulCreates.incrementAndGet();
        return winner;
      }
      uniquenessConflicts.incrementAndGet();
      awaitRaceLatch(winnerConfigured, "winner post-addUser identity and enabled configuration");
      UserModel visibleWinner = accountsByUsername.get(username);
      org.junit.jupiter.api.Assertions.assertSame(winner, visibleWinner);
      assertEquals("concurrent-winner-id", visibleWinner.getId());
      assertEquals(identityId,
          visibleWinner.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE));
      org.junit.jupiter.api.Assertions.assertTrue(visibleWinner.isEnabled());
      throw new IllegalStateException("deterministic username uniqueness conflict");
    });

    var executor = java.util.concurrent.Executors.newFixedThreadPool(2);
    try {
      var first = executor.submit(() -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));
      var second = executor.submit(() -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));
      UserModel firstResult = first.get(15, java.util.concurrent.TimeUnit.SECONDS);
      UserModel secondResult = second.get(15, java.util.concurrent.TimeUnit.SECONDS);

      org.junit.jupiter.api.Assertions.assertSame(winner, firstResult);
      org.junit.jupiter.api.Assertions.assertSame(firstResult, secondResult);
      assertEquals("concurrent-winner-id", firstResult.getId());
      assertEquals(identityId,
          firstResult.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE));
      org.junit.jupiter.api.Assertions.assertTrue(firstResult.isEnabled());
      assertEquals(2, createCalls.get(), "both invocations reach the create boundary");
      assertEquals(1, successfulCreates.get(), "exactly one fake account is created");
      assertEquals(1, uniquenessConflicts.get(), "the other create observes the uniqueness conflict");
      assertEquals(4, totalSearches.get(), "both initial misses and both independent read-backs occur");
      assertEquals(2, configurationEffects.get(), "identity and enabled setters each take effect once");
      assertEquals(identityId, winnerIdentity.get(), "identity is configured after addUser returns");
      org.junit.jupiter.api.Assertions.assertTrue(winnerEnabled.get());
      org.junit.jupiter.api.Assertions.assertEquals(1, accountsByUsername.size());
      org.junit.jupiter.api.Assertions.assertSame(winner, accountsByUsername.get(username));
      verify(users, org.mockito.Mockito.never()).removeUser(org.mockito.ArgumentMatchers.eq(realm),
          org.mockito.ArgumentMatchers.any(UserModel.class));
    } finally {
      executor.shutdownNow();
      org.junit.jupiter.api.Assertions.assertTrue(
          executor.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS), "executor terminates");
    }
  }

  private static void awaitRaceLatch(java.util.concurrent.CountDownLatch latch, String description) {
    try {
      org.junit.jupiter.api.Assertions.assertTrue(
          latch.await(10, java.util.concurrent.TimeUnit.SECONDS), "timed out waiting for " + description);
    } catch (InterruptedException failure) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("interrupted waiting for " + description, failure);
    }
  }

  private static void awaitRaceBarrier(java.util.concurrent.CyclicBarrier barrier, String description) {
    try {
      barrier.await(10, java.util.concurrent.TimeUnit.SECONDS);
    } catch (InterruptedException failure) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("interrupted waiting for " + description, failure);
    } catch (java.util.concurrent.BrokenBarrierException | java.util.concurrent.TimeoutException failure) {
      throw new IllegalStateException("timed out waiting for " + description, failure);
    }
  }

  @Test
  void signupProvisioningAdoptsConcurrentExactIdentityAccountWhenUsernameCreationLosesRace() {
    String identityId = "mailto:race@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var racedWinner = mock(UserModel.class);
    when(racedWinner.isEnabled()).thenReturn(true);
    when(racedWinner.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(Stream.empty(), Stream.of(racedWinner));
    String username = "wallet-" + hexDigest(identityId);
    when(users.addUser(realm, null, username, true, true))
        .thenThrow(new IllegalStateException("concurrent username insert won"));

    var resolved = WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true);

    assertEquals(racedWinner, resolved);
  }

  @Test
  void resolvesOneEnabledExactIdentifierMapping() {
    String identityId = "mailto:Alice@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var user = mock(UserModel.class);
    when(user.isEnabled()).thenReturn(true);
    when(user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE,
        identityId)).thenReturn(Stream.of(user));

    assertEquals(user, WalletLoginAccountMapping.findUniqueEnabledUser(users, realm, identityId));
  }

  @Test
  void booleanMappingLookupUsesTheUniqueAttributeQueryAndClosesItsStream() {
    String identityId = "mailto:Alice@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    var user = mock(UserModel.class);
    when(user.isEnabled()).thenReturn(true);
    when(user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)).thenReturn(Stream.of(user));

    org.junit.jupiter.api.Assertions.assertTrue(
        WalletLoginAccountMapping.hasUniqueEnabledMapping(users, realm, identityId));
    verify(users).searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId);
  }

  @Test
  void signupDoesNotProvisionWhenInitialIdentityLookupReturnsNoStream() {
    String identityId = "mailto:lookup-stream-unavailable@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)).thenReturn(null);

    org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));

    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).addUser(
        org.mockito.ArgumentMatchers.eq(realm), org.mockito.ArgumentMatchers.isNull(),
        org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.eq(true),
        org.mockito.ArgumentMatchers.eq(true));
  }

  @Test
  void signupOccupancyLookupDoesNotTreatUnavailableSearchAsNoExistingMapping() {
    String identityId = "mailto:occupancy-lookup-unavailable@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)).thenReturn(null);

    org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.hasUniqueMappingIncludingDisabled(users, realm, identityId));
  }

  @Test
  void identityMappingCandidateCapCannotMasqueradeAsEmptyAndCreateUser() {
    String identityId = "mailto:too-many-candidates@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(java.util.stream.IntStream.range(0, 65).mapToObj(index -> mock(UserModel.class)));

    org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.ensureEnabledUser(users, realm, identityId, true));

    org.mockito.Mockito.verify(users, org.mockito.Mockito.never()).addUser(
        org.mockito.ArgumentMatchers.eq(realm), org.mockito.ArgumentMatchers.isNull(),
        org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.eq(true),
        org.mockito.ArgumentMatchers.eq(true));
  }

  @Test
  void enabledMappingLookupCandidateCapIsUnavailableInsteadOfMissing() {
    String identityId = "mailto:enabled-too-many-candidates@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(java.util.stream.IntStream.range(0, 65).mapToObj(index -> mock(UserModel.class)));

    org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.hasUniqueEnabledMapping(users, realm, identityId));
  }

  @Test
  void occupancyLookupCandidateCapIsUnavailableInsteadOfUnoccupied() {
    String identityId = "mailto:occupancy-too-many-candidates@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId))
        .thenReturn(java.util.stream.IntStream.range(0, 65).mapToObj(index -> mock(UserModel.class)));

    org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
        () -> WalletLoginAccountMapping.hasUniqueMappingIncludingDisabled(users, realm, identityId));
  }

  @Test
  void rejectsMissingDuplicateAndDisabledMappings() {
    String identityId = "mailto:Alice@example.org";
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    when(users.searchForUserByUserAttributeStream(realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE,
        identityId)).thenReturn(Stream.empty());
    assertNull(WalletLoginAccountMapping.findUniqueEnabledUser(users, realm, identityId));

    var first = mock(UserModel.class);
    var second = mock(UserModel.class);
    when(first.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(second.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE,
        identityId)).thenReturn(Stream.of(first, second));
    assertNull(WalletLoginAccountMapping.findUniqueEnabledUser(users, realm, identityId));

    var enabled = mock(UserModel.class);
    var disabled = mock(UserModel.class);
    when(enabled.isEnabled()).thenReturn(true);
    when(disabled.isEnabled()).thenReturn(false);
    when(enabled.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(disabled.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    when(users.searchForUserByUserAttributeStream(realm,
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId)).thenReturn(Stream.of(enabled, disabled));
    org.junit.jupiter.api.Assertions.assertFalse(
        WalletLoginAccountMapping.hasUniqueMappingIncludingDisabled(users, realm, identityId));
  }
}
