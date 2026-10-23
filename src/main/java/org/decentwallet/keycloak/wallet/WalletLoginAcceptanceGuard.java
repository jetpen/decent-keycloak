package org.decentwallet.keycloak.wallet;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** Process-local gate hiding accepted state while publication is incomplete or failed. */
final class WalletLoginAcceptanceGuard {
  private static final WalletLoginAcceptanceGuard PROCESS_LOCAL = new WalletLoginAcceptanceGuard();

  private final ConcurrentMap<String, Publication> publications = new ConcurrentHashMap<>();

  static WalletLoginAcceptanceGuard processLocal() { return PROCESS_LOCAL; }

  boolean begin(String receiptKey, Instant expiresAt, Instant now) {
    publications.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().expiresAt()));
    return publications.putIfAbsent(receiptKey, new Publication(State.PUBLISHING, expiresAt)) == null;
  }

  void markPublished(String receiptKey, Instant now) {
    Publication current = publications.get(receiptKey);
    if (current == null || current.state() != State.PUBLISHING || !now.isBefore(current.expiresAt())) {
      throw new IllegalStateException("wallet acceptance publication state is unavailable");
    }
    publications.remove(receiptKey, current);
  }

  void markFailed(String receiptKey, Instant now) {
    publications.computeIfPresent(receiptKey, (key, current) ->
        now.isBefore(current.expiresAt()) ? new Publication(State.FAILED, current.expiresAt()) : null);
  }

  boolean isUnavailable(String receiptKey, Instant now) {
    Publication current = publications.get(receiptKey);
    if (current == null) return false;
    if (!now.isBefore(current.expiresAt())) {
      publications.remove(receiptKey, current);
      return false;
    }
    return true;
  }

  private enum State { PUBLISHING, FAILED }
  private record Publication(State state, Instant expiresAt) { }
}
