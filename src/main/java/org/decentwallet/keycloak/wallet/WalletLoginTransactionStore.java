package org.decentwallet.keycloak.wallet;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.keycloak.models.SingleUseObjectProvider;

/** Stores the pending state for one provider-hosted wallet proof transaction. */
public final class WalletLoginTransactionStore {
  public static final long TRANSACTION_LIFESPAN_SECONDS = 300;
  private static final String NOTE_REALM = "realm_id";
  private static final String NOTE_CLIENT = "client_id";
  private static final String NOTE_ROOT_SESSION = "root_session_id";
  private static final String NOTE_TAB = "tab_id";
  private static final String NOTE_REDIRECT = "redirect_uri";
  private static final String NOTE_ORIGIN = "canonical_origin";
  private static final String NOTE_CHALLENGE = "challenge";
  private static final String NOTE_CSRF = "csrf_token";
  private static final String NOTE_EXPIRES_AT = "expires_at_epoch_second";
  private static final String ACCEPTED_PREFIX = "decent-wallet-login-v1:accepted:";
  private static final String CALLBACK_PREFIX = "decent-wallet-login-v1:callback:";
  private static final String INVALID_ATTEMPT_PREFIX = "decent-wallet-login-v1:invalid-attempt:";
  private static final String LOCK_PREFIX = "decent-wallet-login-v1:abuse-lock:";
  private static final String IDENTITY_LOOKUP_PREFIX = "decent-wallet-login-v1:identity-lookup:browser-client:";
  private static final int MAX_INVALID_ATTEMPTS = 5;
  private static final long IDENTITY_LOOKUP_LEASE_SECONDS = 20;
  private static final String NOTE_PROOF_DIGEST = "proof_digest";
  private static final String NOTE_IDENTITY = "identity_id";
  private static final String NOTE_PUBLIC_KEY = "public_key";
  private static final String NOTE_STATUS = "status";
  private static final String NOTE_RECEIPT_EXPIRES = "receipt_expires_at";
  private static final String HANDLE_PREFIX = "decent-wallet-login-v1:transaction:";

  private final SingleUseObjectProvider singleUseObjects;
  private final SecureRandom random;
  private final Clock clock;

  public WalletLoginTransactionStore(SingleUseObjectProvider singleUseObjects,
      SecureRandom random, Clock clock) {
    this.singleUseObjects = Objects.requireNonNull(singleUseObjects);
    this.random = Objects.requireNonNull(random);
    this.clock = Objects.requireNonNull(clock);
  }

  public IssuedTransaction issue(Binding binding) {
    validateBinding(binding);
    if (singleUseObjects.contains(browserClientLockKey(binding))) {
      throw new IllegalStateException("wallet browser/client admission is temporarily locked");
    }
    byte[] handleBytes = randomBytes(32);
    byte[] nonce = randomBytes(32);
    byte[] csrfBytes = randomBytes(32);
    String handle = encode(handleBytes);
    String csrf = encode(csrfBytes);
    String challenge = encode(sha256(nonce));
    Map<String, String> notes = new HashMap<>();
    notes.put(NOTE_REALM, binding.realmId());
    notes.put(NOTE_CLIENT, binding.clientId());
    notes.put(NOTE_ROOT_SESSION, binding.rootSessionId());
    notes.put(NOTE_TAB, binding.tabId());
    notes.put(NOTE_REDIRECT, binding.redirectUri());
    notes.put(NOTE_ORIGIN, binding.canonicalOrigin());
    notes.put(NOTE_CHALLENGE, challenge);
    notes.put(NOTE_CSRF, csrf);
    java.time.Instant expiresAt = clock.instant().plusSeconds(TRANSACTION_LIFESPAN_SECONDS);
    notes.put(NOTE_EXPIRES_AT, Long.toString(expiresAt.getEpochSecond()));
    // The locator is independently random and never persisted in plaintext.
    if (!singleUseObjects.putIfAbsent(storageKey(handle), TRANSACTION_LIFESPAN_SECONDS)) {
      throw new IllegalStateException("wallet transaction handle collision");
    }
    if (!singleUseObjects.replace(storageKey(handle), notes)) {
      singleUseObjects.remove(storageKey(handle));
      throw new IllegalStateException("wallet transaction publication failed");
    }
    return new IssuedTransaction(handle, challenge, csrf, expiresAt);
  }

  /** Reads pending transaction state without consuming it. */
  public Optional<PendingTransaction> load(String handle, Binding expectedBinding) {
    Optional<PendingTransaction> pending = load(handle);
    if (pending.isEmpty() || expectedBinding == null || !pending.get().binding().equals(expectedBinding)) {
      return Optional.empty();
    }
    return pending;
  }

  public Optional<PendingTransaction> load(String handle) {
    if (!validHandle(handle)) return Optional.empty();
    Map<String, String> notes = singleUseObjects.get(storageKey(handle));
    if (notes == null || !complete(notes) || expired(notes)) return Optional.empty();
    try {
      Binding binding = new Binding(notes.get(NOTE_REALM), notes.get(NOTE_CLIENT),
          notes.get(NOTE_ROOT_SESSION), notes.get(NOTE_TAB), notes.get(NOTE_REDIRECT), notes.get(NOTE_ORIGIN));
      validateBinding(binding);
      String challenge = notes.get(NOTE_CHALLENGE);
      String csrfToken = notes.get(NOTE_CSRF);
      if (!validToken(challenge) || !validToken(csrfToken)) return Optional.empty();
      return Optional.of(new PendingTransaction(binding, challenge, csrfToken));
    } catch (IllegalArgumentException ex) {
      return Optional.empty();
    }
  }

  /**
   * Consumes only after the caller has verified the signature using the exact current Registry key.
   * The atomic remove is this transaction's single-winner point across Keycloak nodes.
   */
  public Optional<PendingTransaction> consume(String handle, Binding expectedBinding,
      String expectedChallenge, String expectedCsrfToken) {
    if (!validHandle(handle) || expectedBinding == null || !validToken(expectedChallenge)
        || !validToken(expectedCsrfToken)) return Optional.empty();
    Map<String, String> notes = singleUseObjects.get(storageKey(handle));
    Optional<PendingTransaction> pending = decode(notes);
    if (pending.isEmpty()) return Optional.empty();
    PendingTransaction current = pending.get();
    if (!current.binding().equals(expectedBinding)
        || !constantTimeEquals(current.challenge(), expectedChallenge)
        || !constantTimeEquals(current.csrfToken(), expectedCsrfToken)) return Optional.empty();
    Map<String, String> removed = singleUseObjects.remove(storageKey(handle));
    Optional<PendingTransaction> consumed = decode(removed);
    if (consumed.isEmpty()) return Optional.empty();
    PendingTransaction winner = consumed.get();
    if (!winner.binding().equals(expectedBinding)
        || !constantTimeEquals(winner.challenge(), expectedChallenge)
        || !constantTimeEquals(winner.csrfToken(), expectedCsrfToken)) return Optional.empty();
    return consumed;
  }

  public void markAccepted(String handle, Binding binding, String proofDigest,
      String identityId, String publicKey, String csrfToken) {
    if (!validHandle(handle) || binding == null || blank(proofDigest) || blank(identityId)
        || blank(publicKey) || !validToken(csrfToken)) {
      throw new IllegalArgumentException("accepted wallet transaction fields are required");
    }
    validateBinding(binding);
    String receiptKey = acceptedKey(handle);
    Map<String, String> receipt = new HashMap<>();
    receipt.put(NOTE_REALM, binding.realmId());
    receipt.put(NOTE_CLIENT, binding.clientId());
    receipt.put(NOTE_ROOT_SESSION, binding.rootSessionId());
    receipt.put(NOTE_TAB, binding.tabId());
    receipt.put(NOTE_REDIRECT, binding.redirectUri());
    receipt.put(NOTE_ORIGIN, binding.canonicalOrigin());
    receipt.put(NOTE_PROOF_DIGEST, proofDigest);
    receipt.put(NOTE_IDENTITY, identityId);
    receipt.put(NOTE_PUBLIC_KEY, publicKey);
    receipt.put(NOTE_STATUS, "accepted");
    receipt.put(NOTE_CSRF, csrfToken);
    receipt.put(NOTE_RECEIPT_EXPIRES, Long.toString(clock.instant().plusSeconds(TRANSACTION_LIFESPAN_SECONDS).getEpochSecond()));
    // Publish the one-use callback gate before the visible accepted receipt.
    // Status polling cannot advertise ACCEPTED until callback consumption is ready.
    String callbackKey = callbackKey(handle);
    if (!singleUseObjects.putIfAbsent(callbackKey, TRANSACTION_LIFESPAN_SECONDS)) {
      throw new IllegalStateException("wallet callback gate already exists");
    }
    if (!singleUseObjects.replace(callbackKey, Map.of(NOTE_STATUS, "pending"))) {
      singleUseObjects.remove(callbackKey);
      throw new IllegalStateException("wallet callback gate publication failed");
    }

    // Transaction-key removal grants this request the one-winner capability;
    // only that capability may create the accepted receipt. A duplicate caller
    // never invokes this method after losing consume().
    if (!singleUseObjects.putIfAbsent(receiptKey, TRANSACTION_LIFESPAN_SECONDS)) {
      singleUseObjects.remove(callbackKey);
      throw new IllegalStateException("wallet transaction receipt already exists");
    }
    if (!singleUseObjects.replace(receiptKey, receipt)) {
      singleUseObjects.remove(receiptKey);
      singleUseObjects.remove(callbackKey);
      throw new IllegalStateException("wallet transaction receipt publication failed");
    }
  }

  private static boolean validCallbackGate(Map<String, String> gate) {
    return gate != null && "pending".equals(gate.get(NOTE_STATUS));
  }

  private static String callbackKey(String handle) {
    return CALLBACK_PREFIX + hex(sha256(handle.getBytes(StandardCharsets.US_ASCII)));
  }

  public Optional<AcceptedTransaction> takeAccepted(String handle, Binding expectedBinding) {
    if (!validHandle(handle)) return Optional.empty();
    Map<String, String> receipt = singleUseObjects.get(acceptedKey(handle));
    if (!validAcceptedReceipt(receipt, expectedBinding)) return Optional.empty();
    Map<String, String> callbackGate = singleUseObjects.remove(callbackKey(handle));
    if (!validCallbackGate(callbackGate)) return Optional.empty();
    Map<String, String> retainedReceipt = singleUseObjects.get(acceptedKey(handle));
    if (!validAcceptedReceipt(retainedReceipt, expectedBinding)) return Optional.empty();
    return Optional.of(new AcceptedTransaction(retainedReceipt.get(NOTE_IDENTITY),
        retainedReceipt.get(NOTE_PUBLIC_KEY), retainedReceipt.get(NOTE_PROOF_DIGEST),
        decodeBinding(retainedReceipt)));
  }

  public Optional<AcceptedTransaction> peekAccepted(String handle) {
    if (!validHandle(handle)) return Optional.empty();
    Map<String, String> receipt = singleUseObjects.get(acceptedKey(handle));
    if (receipt == null || !validAcceptedReceipt(receipt, null)) return Optional.empty();
    return Optional.of(new AcceptedTransaction(receipt.get(NOTE_IDENTITY), receipt.get(NOTE_PUBLIC_KEY),
        receipt.get(NOTE_PROOF_DIGEST), decodeBinding(receipt)));
  }

  public boolean callbackGateAvailable(String handle, Binding expectedBinding) {
    if (!validHandle(handle) || expectedBinding == null) return false;
    Map<String, String> receipt = singleUseObjects.get(acceptedKey(handle));
    return validAcceptedReceipt(receipt, expectedBinding)
        && validCallbackGate(singleUseObjects.get(callbackKey(handle)));
  }

  public boolean acceptedCsrfMatches(String handle, Binding expectedBinding, String csrfToken) {
    if (!validHandle(handle) || expectedBinding == null || !validToken(csrfToken)) return false;
    Map<String, String> receipt = singleUseObjects.get(acceptedKey(handle));
    return validAcceptedReceipt(receipt, expectedBinding)
        && constantTimeEquals(receipt.get(NOTE_CSRF), csrfToken);
  }

  public Optional<AcceptedTransaction> getAccepted(String handle, Binding expectedBinding) {
    if (!validHandle(handle)) return Optional.empty();
    Map<String, String> receipt = singleUseObjects.get(acceptedKey(handle));
    if (!validAcceptedReceipt(receipt, expectedBinding)) return Optional.empty();
    try {
      return Optional.of(new AcceptedTransaction(receipt.get(NOTE_IDENTITY), receipt.get(NOTE_PUBLIC_KEY),
          receipt.get(NOTE_PROOF_DIGEST), decodeBinding(receipt)));
    } catch (RuntimeException ex) {
      return Optional.empty();
    }
  }

  private boolean validAcceptedReceipt(Map<String, String> receipt, Binding expectedBinding) {
    if (receipt == null || !completeBinding(receipt) || !"accepted".equals(receipt.get(NOTE_STATUS))
        || expiredReceipt(receipt) || !validToken(receipt.get(NOTE_CSRF))
        || blank(receipt.get(NOTE_PROOF_DIGEST))
        || blank(receipt.get(NOTE_IDENTITY)) || blank(receipt.get(NOTE_PUBLIC_KEY))) return false;
    try {
      Binding actual = decodeBinding(receipt);
      return expectedBinding == null || actual.equals(expectedBinding);
    } catch (RuntimeException ex) {
      return false;
    }
  }

  private boolean expiredReceipt(Map<String, String> receipt) {
    try { return !clock.instant().isBefore(java.time.Instant.ofEpochSecond(Long.parseLong(receipt.get(NOTE_RECEIPT_EXPIRES)))); }
    catch (RuntimeException e) { return true; }
  }

  private static Binding decodeBinding(Map<String, String> notes) {
    Binding binding = new Binding(notes.get(NOTE_REALM), notes.get(NOTE_CLIENT), notes.get(NOTE_ROOT_SESSION),
        notes.get(NOTE_TAB), notes.get(NOTE_REDIRECT), notes.get(NOTE_ORIGIN));
    validateBinding(binding);
    return binding;
  }

  private static boolean completeBinding(Map<String, String> notes) {
    return notes.containsKey(NOTE_REALM) && notes.containsKey(NOTE_CLIENT)
        && notes.containsKey(NOTE_ROOT_SESSION) && notes.containsKey(NOTE_TAB)
        && notes.containsKey(NOTE_REDIRECT) && notes.containsKey(NOTE_ORIGIN);
  }

  public boolean invalidAttemptLimitReached(String handle) {
    if (!validHandle(handle)) return true;
    Map<String, String> notes = singleUseObjects.get(storageKey(handle));
    Optional<PendingTransaction> pending = decode(notes);
    if (pending.isEmpty()) return true;
    if (singleUseObjects.contains(transactionLockKey(handle))) return true;
    if (invalidAttemptCount(handle) < MAX_INVALID_ATTEMPTS) return false;
    lockTransactionAndBrowserClient(handle, pending.get().binding());
    return true;
  }

  /** Claims one of five shared per-transaction invalid-proof slots; not replay protection. */
  public boolean recordInvalidAttempt(String handle) {
    if (!validHandle(handle)) return false;
    Optional<PendingTransaction> pending = load(handle);
    if (pending.isEmpty()) return false;
    for (int slot = 1; slot <= MAX_INVALID_ATTEMPTS; slot++) {
      if (singleUseObjects.putIfAbsent(invalidAttemptSlotKey(handle, slot), TRANSACTION_LIFESPAN_SECONDS)) {
        if (slot == MAX_INVALID_ATTEMPTS) {
          lockTransactionAndBrowserClient(handle, pending.get().binding());
        }
        return true;
      }
    }
    lockTransactionAndBrowserClient(handle, pending.get().binding());
    return false;
  }

  private int invalidAttemptCount(String handle) {
    int attempts = 0;
    for (int slot = 1; slot <= MAX_INVALID_ATTEMPTS; slot++) {
      if (singleUseObjects.contains(invalidAttemptSlotKey(handle, slot))) attempts++;
    }
    return attempts;
  }

  private void lockTransactionAndBrowserClient(String handle, Binding binding) {
    singleUseObjects.putIfAbsent(transactionLockKey(handle), TRANSACTION_LIFESPAN_SECONDS);
    singleUseObjects.putIfAbsent(browserClientLockKey(binding), TRANSACTION_LIFESPAN_SECONDS);
  }

  private static String invalidAttemptSlotKey(String handle, int slot) {
    return INVALID_ATTEMPT_PREFIX + storageKey(handle).substring(HANDLE_PREFIX.length()) + ":" + slot;
  }

  private static String transactionLockKey(String handle) {
    return LOCK_PREFIX + "transaction:" + storageKey(handle).substring(HANDLE_PREFIX.length());
  }

  private static String browserClientLockKey(Binding binding) {
    String scope = binding.realmId() + "\0" + binding.clientId() + "\0" + binding.rootSessionId();
    return LOCK_PREFIX + "browser-client:" + hex(sha256(scope.getBytes(StandardCharsets.UTF_8)));
  }

  /** Claims a short per-transaction resolver window; it expires rather than being owner-released. */
  public boolean tryAcquireIdentityLookup(String handle) {
    if (!validHandle(handle)) return false;
    Optional<PendingTransaction> pending = load(handle);
    if (pending.isEmpty() || invalidAttemptLimitReached(handle)) return false;
    return singleUseObjects.putIfAbsent(identityLookupScopeKey(pending.get().binding()),
        IDENTITY_LOOKUP_LEASE_SECONDS);
  }

  /** Promotes the shared resolver admission key to an emergency block if a process cannot be killed. */
  public void blockIdentityLookups(String handle, Binding binding) {
    if (!validHandle(handle) || binding == null) return;
    validateBinding(binding);
    // The active resolver already owns this same admission key; writing the longer TTL
    // prevents sibling handles from acquiring it after a kill failure.
    singleUseObjects.put(identityLookupScopeKey(binding), TRANSACTION_LIFESPAN_SECONDS,
        Map.of(NOTE_STATUS, "blocked"));
    lockTransactionAndBrowserClient(handle, binding);
  }

  private static String identityLookupScopeKey(Binding binding) {
    String scope = binding.realmId() + "\0" + binding.clientId() + "\0" + binding.rootSessionId();
    return IDENTITY_LOOKUP_PREFIX + hex(sha256(scope.getBytes(StandardCharsets.UTF_8)));
  }

  private static String acceptedKey(String handle) {
    return ACCEPTED_PREFIX + hex(sha256(handle.getBytes(StandardCharsets.US_ASCII)));
  }

  public boolean isExpired(IssuedTransaction issued) {
    return issued == null || !clock.instant().isBefore(issued.expiresAt());
  }

  private Optional<PendingTransaction> decode(Map<String, String> notes) {
    if (notes == null || !complete(notes) || expired(notes)) return Optional.empty();
    try {
      Binding binding = new Binding(notes.get(NOTE_REALM), notes.get(NOTE_CLIENT),
          notes.get(NOTE_ROOT_SESSION), notes.get(NOTE_TAB), notes.get(NOTE_REDIRECT), notes.get(NOTE_ORIGIN));
      validateBinding(binding);
      String challenge = notes.get(NOTE_CHALLENGE);
      String csrf = notes.get(NOTE_CSRF);
      if (!validToken(challenge) || !validToken(csrf)) return Optional.empty();
      return Optional.of(new PendingTransaction(binding, challenge, csrf));
    } catch (IllegalArgumentException ex) {
      return Optional.empty();
    }
  }

  private static boolean complete(Map<String, String> notes) {
    return notes.containsKey(NOTE_REALM) && notes.containsKey(NOTE_CLIENT)
        && notes.containsKey(NOTE_ROOT_SESSION) && notes.containsKey(NOTE_TAB)
        && notes.containsKey(NOTE_REDIRECT) && notes.containsKey(NOTE_ORIGIN)
        && notes.containsKey(NOTE_CHALLENGE) && notes.containsKey(NOTE_CSRF)
        && notes.containsKey(NOTE_EXPIRES_AT);
  }

  private boolean expired(Map<String, String> notes) {
    try {
      return !clock.instant().isBefore(java.time.Instant.ofEpochSecond(
          Long.parseLong(notes.get(NOTE_EXPIRES_AT))));
    } catch (RuntimeException ex) {
      return true;
    }
  }

  private byte[] randomBytes(int length) {
    byte[] value = new byte[length];
    random.nextBytes(value);
    return value;
  }

  private static String storageKey(String handle) {
    return HANDLE_PREFIX + hex(sha256(handle.getBytes(StandardCharsets.US_ASCII)));
  }

  private static void validateBinding(Binding binding) {
    if (binding == null || blank(binding.realmId()) || blank(binding.clientId())
        || blank(binding.rootSessionId()) || blank(binding.tabId()) || blank(binding.redirectUri())) {
      throw new IllegalArgumentException("wallet login binding is incomplete");
    }
    URI redirect = URI.create(binding.redirectUri());
    if (!redirect.isAbsolute() || !"https".equalsIgnoreCase(redirect.getScheme()) || redirect.getHost() == null) {
      throw new IllegalArgumentException("wallet login redirect must be absolute HTTPS");
    }
    URI origin = URI.create(binding.canonicalOrigin());
    if (!origin.isAbsolute() || !"https".equalsIgnoreCase(origin.getScheme()) || origin.getHost() == null
        || origin.getRawAuthority().contains("@") || origin.getRawPath() != null && !origin.getRawPath().isEmpty()
        || origin.getRawQuery() != null || origin.getRawFragment() != null) {
      throw new IllegalArgumentException("wallet login origin must be an HTTPS origin");
    }
  }

  private static boolean blank(String value) { return value == null || value.isBlank(); }
  private static boolean validHandle(String value) { return validToken(value); }
  private static boolean validToken(String value) {
    if (value == null || value.length() != 43 || !value.matches("[A-Za-z0-9_-]{43}")) return false;
    try { return Base64.getUrlDecoder().decode(value).length == 32; }
    catch (IllegalArgumentException ex) { return false; }
  }
  private static byte[] sha256(byte[] input) {
    try { return MessageDigest.getInstance("SHA-256").digest(input); }
    catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
  }
  private static String encode(byte[] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
  private static String hex(byte[] bytes) { return java.util.HexFormat.of().formatHex(bytes); }
  private static boolean constantTimeEquals(String a, String b) {
    return MessageDigest.isEqual(a.getBytes(StandardCharsets.US_ASCII), b.getBytes(StandardCharsets.US_ASCII));
  }

  public record Binding(String realmId, String clientId, String rootSessionId, String tabId,
      String redirectUri, String canonicalOrigin) {}
  public record IssuedTransaction(String handle, String challenge, String csrfToken, java.time.Instant expiresAt) {}
  public record PendingTransaction(Binding binding, String challenge, String csrfToken) {}
  public record AcceptedTransaction(String identityId, String publicKey, String proofDigest, Binding binding) {}
}
