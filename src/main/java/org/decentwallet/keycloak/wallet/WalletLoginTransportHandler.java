package org.decentwallet.keycloak.wallet;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/** Provider-owned wallet GET/POST seam. The resolver must return the exact current Registry key. */
public final class WalletLoginTransportHandler {
  private static final org.jboss.logging.Logger LOG =
      org.jboss.logging.Logger.getLogger(WalletLoginTransportHandler.class);
  private static final int MAX_ACCOUNT_DIRECTORY_CANDIDATES = 64;
  static final int MAX_PROOF_BYTES = 8192;
  private final WalletLoginTransactionStore transactions;
  private final WalletLoginIdentityResolver identities;
  private final String walletOrigin;
  private final String idpOrigin;
  private final WalletLoginAccountResolver accounts;
  private final boolean acceptSignup;
  private final WalletLoginTransactionStore transactionStore;
  private final WalletLoginVerifier verifier = new WalletLoginVerifier();

  public WalletLoginTransportHandler(WalletLoginTransactionStore transactions,
      WalletLoginIdentityResolver identities, String walletOrigin) {
    this(transactions, identities, walletOrigin, null, null, true, transactions);
  }

  public WalletLoginTransportHandler(WalletLoginTransactionStore transactions,
      WalletLoginIdentityResolver identities, String walletOrigin, String idpOrigin) {
    this(transactions, identities, walletOrigin, idpOrigin, null, true, transactions);
  }

  public WalletLoginTransportHandler(WalletLoginTransactionStore transactions,
      WalletLoginIdentityResolver identities, String walletOrigin, String idpOrigin,
      WalletLoginAccountResolver accounts) {
    this(transactions, identities, walletOrigin, idpOrigin, accounts, true, transactions);
  }

  public WalletLoginTransportHandler(WalletLoginTransactionStore transactions,
      WalletLoginIdentityResolver identities, String walletOrigin, String idpOrigin,
      WalletLoginAccountResolver accounts, boolean acceptSignup) {
    this(transactions, identities, walletOrigin, idpOrigin, accounts, acceptSignup, transactions);
  }

  public WalletLoginTransportHandler(WalletLoginTransactionStore transactions,
      WalletLoginIdentityResolver identities, String walletOrigin, String idpOrigin,
      WalletLoginAccountResolver accounts, boolean acceptSignup,
      WalletLoginTransactionStore transactionStore) {
    this.transactions = java.util.Objects.requireNonNull(transactions);
    this.identities = identities;
    this.walletOrigin = walletOrigin == null || walletOrigin.isBlank()
        ? null : normalizeOrigin(walletOrigin);
    this.idpOrigin = idpOrigin == null ? null : normalizeOrigin(idpOrigin);
    this.accounts = accounts;
    this.acceptSignup = acceptSignup;
    this.transactionStore = java.util.Objects.requireNonNull(transactionStore);
  }

  HttpResult getChallenge(String handle, String requestOrigin, String fetchSite,
      String idpOrigin) {
    boolean nativeMetadata = requestOrigin == null && fetchSite == null;
    return getChallenge(handle, requestOrigin, fetchSite,
        nativeMetadata ? null : "cors", nativeMetadata ? null : "empty", idpOrigin);
  }

  HttpResult getChallenge(String handle, String requestOrigin, String fetchSite,
      String fetchMode, String fetchDest, String idpOrigin) {
    var pending = transactions.load(handle);
    if (pending.isEmpty()) return HttpResult.empty(404);
    if (!sameOrigin(idpOrigin, pending.get().binding().canonicalOrigin())
        || this.idpOrigin != null && !sameOrigin(idpOrigin, this.idpOrigin)) return HttpResult.empty(404);
    boolean nativeWallet = browserMetadataAbsent(requestOrigin, fetchSite, fetchMode, fetchDest);
    if (!nativeWallet && !validBrowserRequest(requestOrigin, fetchSite, fetchMode, fetchDest)) {
      return HttpResult.empty(403);
    }
    return HttpResult.json(200, Map.of("profile", WalletLoginProof.PROFILE,
        "challenge", pending.get().challenge(), "csrf_token", pending.get().csrfToken()));
  }

  HttpResult submitProof(String handle, String requestOrigin, String fetchSite,
      String contentType, String csrfToken, byte[] body, String idpOrigin) {
    boolean nativeMetadata = requestOrigin == null && fetchSite == null;
    return submitProof(handle, requestOrigin, fetchSite,
        nativeMetadata ? null : "cors", nativeMetadata ? null : "empty",
        contentType, csrfToken, body, idpOrigin);
  }

  HttpResult submitProof(String handle, String requestOrigin, String fetchSite,
      String fetchMode, String fetchDest, String contentType, String csrfToken,
      byte[] body, String idpOrigin) {
    return submitProof(handle, requestOrigin, fetchSite, fetchMode, fetchDest,
        contentType, csrfToken, body, idpOrigin, null);
  }

  HttpResult submitProof(String handle, String requestOrigin, String fetchSite,
      String fetchMode, String fetchDest, String contentType, String csrfToken,
      byte[] body, String idpOrigin, WalletLoginTransactionStore.Intent expectedIntent) {
    var pending = transactions.load(handle);
    if (pending.isEmpty()) return submitAcceptedRetry(handle, requestOrigin, fetchSite,
        fetchMode, fetchDest, contentType, csrfToken, body, idpOrigin);
    if (expectedIntent != null && pending.get().intent() != expectedIntent) return HttpResult.empty(403);
    WalletLoginTransactionStore.Binding binding = pending.get().binding();
    if (!sameOrigin(idpOrigin, binding.canonicalOrigin())
        || this.idpOrigin != null && !sameOrigin(idpOrigin, this.idpOrigin)) return HttpResult.empty(404);
    boolean nativeWalletRequest = csrfToken == null
        && browserMetadataAbsent(requestOrigin, fetchSite, fetchMode, fetchDest);
    if (!nativeWalletRequest
        && !validWalletBrowserRequest(requestOrigin, fetchSite, fetchMode, fetchDest)) {
      return HttpResult.empty(403);
    }
    if (!"application/json".equalsIgnoreCase(
        contentType == null ? "" : contentType.split(";", 2)[0].trim())
        || body == null || body.length == 0 || body.length > MAX_PROOF_BYTES) {
      return HttpResult.empty(contentType == null || !contentType.startsWith("application/json") ? 415 : 413);
    }
    if (!nativeWalletRequest && !constantTimeEquals(pending.get().csrfToken(), csrfToken)) {
      return HttpResult.empty(403);
    }
    if (transactions.invalidAttemptLimitReached(handle)) return HttpResult.empty(429);

    final WalletLoginProof proof;
    try { proof = WalletLoginProof.parse(body); }
    catch (IllegalArgumentException ex) {
      transactions.recordInvalidAttempt(handle);
      return HttpResult.empty(400);
    }
    if (!WalletLoginVerifier.challengeMatches(pending.get().challenge(), proof.challenge())) {
      transactions.recordInvalidAttempt(handle);
      return HttpResult.empty(401);
    }
    String requestId = requestCorrelationId(handle);
    if (identities == null) return HttpResult.empty(503);

    if (!transactions.tryAcquireIdentityLookup(handle)) return HttpResult.empty(429);
    final WalletIdentityKeyResolver.ResolvedIdentityKey identity;
    try {
      identity = identities.resolveExact(proof.identityId());
    } catch (ProcessIdentityResolver.IdentityResolutionException ex) {
      LOG.warnf("Wallet Identity resolver unavailable (request=%s, %s)", requestId, ex.getClass().getSimpleName());
      if (ex.processMayStillRun()) transactions.blockIdentityLookups(handle, binding);
      return HttpResult.empty(503);
    } catch (Exception ex) {
      LOG.warnf("Wallet Identity resolver unavailable (request=%s, %s)", requestId, ex.getClass().getSimpleName());
      return HttpResult.empty(503);
    }
    if (identity == null || !proof.identityId().equals(identity.identityId())) {
      transactions.recordInvalidAttempt(handle);
      return HttpResult.empty(401);
    }
    if (identity.publicKey() == null || identity.publicKey().length != 32) {
      transactions.recordInvalidAttempt(handle);
      return HttpResult.empty(503);
    }
    if (!verifier.verify(proof, pending.get().challenge(), identity.publicKey())) {
      transactions.recordInvalidAttempt(handle);
      return HttpResult.empty(401);
    }
    if (accounts == null) return HttpResult.empty(503);
    WalletLoginTransactionStore.Intent intent = pending.get().intent();
    try {
      boolean mapped = accounts.hasUniqueEnabledUser(proof.identityId());
      if (!mapped) {
        LOG.debugf("Wallet account policy lookup started (signup=%s, registration-enabled=%s)",
            intent == WalletLoginTransactionStore.Intent.SIGNUP, acceptSignup);
        boolean occupied = accounts.hasUniqueMappedUserIncludingDisabled(proof.identityId());
        LOG.debugf("Wallet account policy occupancy observed (occupied=%s)", occupied);
        if (intent != WalletLoginTransactionStore.Intent.SIGNUP || !acceptSignup || occupied) {
          LOG.debugf("Wallet account policy rejected proof (request=%s, signup=%s, registered=%s, occupied=%s)",
              requestId, intent == WalletLoginTransactionStore.Intent.SIGNUP, acceptSignup, occupied);
          return HttpResult.empty(403);
        }
        org.keycloak.models.UserModel provisioned = accounts.ensureEnabledUser(proof.identityId());
        if (provisioned == null || !provisioned.isEnabled()) return HttpResult.empty(503);
        if (!accounts.hasUniqueEnabledUser(proof.identityId())) return HttpResult.empty(503);
      }
    } catch (Exception unavailable) {
      LOG.warnf("Wallet account mapping lookup unavailable (request=%s, %s)", requestId, unavailable.getClass().getSimpleName());
      return HttpResult.empty(503);
    }

    Optional<WalletLoginTransactionStore.PendingTransaction> consumed = transactions.consume(
        handle, binding, pending.get().challenge(), pending.get().csrfToken());
    if (consumed.isEmpty()) return HttpResult.empty(409);
    String digest = hex(sha256(body));
    try {
      transactions.markAccepted(handle, binding, digest, proof.identityId(),
          Base64.getUrlEncoder().withoutPadding().encodeToString(identity.publicKey()), consumed.get().csrfToken(),
          consumed.get().intent());
    } catch (RuntimeException ex) {
      // Nonce is consumed; no OIDC result unless its separate accepted receipt persists.
      return HttpResult.empty(503);
    }
    return HttpResult.json(202, Map.of("status", "pending"));
  }

  private HttpResult submitAcceptedRetry(String handle, String requestOrigin, String fetchSite,
      String fetchMode, String fetchDest, String contentType, String csrfToken, byte[] body, String idpOrigin) {
    var accepted = transactions.peekAccepted(handle);
    if (accepted.isEmpty()) return HttpResult.empty(404);
    WalletLoginTransactionStore.Binding binding = accepted.get().binding();
    if (!sameOrigin(idpOrigin, binding.canonicalOrigin())
        || this.idpOrigin != null && !sameOrigin(idpOrigin, this.idpOrigin)) return HttpResult.empty(404);
    boolean nativeWalletRequest = csrfToken == null
        && browserMetadataAbsent(requestOrigin, fetchSite, fetchMode, fetchDest);
    if (!nativeWalletRequest
        && !validWalletBrowserRequest(requestOrigin, fetchSite, fetchMode, fetchDest)) {
      return HttpResult.empty(403);
    }
    if (!"application/json".equalsIgnoreCase(
        contentType == null ? "" : contentType.split(";", 2)[0].trim())
        || body == null || body.length == 0 || body.length > MAX_PROOF_BYTES) {
      return HttpResult.empty(contentType == null || !contentType.startsWith("application/json") ? 415 : 413);
    }
    if (!nativeWalletRequest && !transactions.acceptedCsrfMatches(handle, binding, csrfToken)) {
      return HttpResult.empty(403);
    }
    String digest = hex(sha256(body));
    return constantTimeEquals(accepted.get().proofDigest(), digest)
        ? HttpResult.json(202, Map.of("status", "accepted")) : HttpResult.empty(409);
  }

  HttpResult getStatus(String handle, String requestOrigin, String fetchSite, String csrfToken,
      String idpOrigin, WalletLoginTransactionStore.Binding initiatingBrowserBinding) {
    return getStatus(handle, requestOrigin, fetchSite,
        fetchSite == null ? null : "cors", fetchSite == null ? null : "empty",
        csrfToken, idpOrigin, initiatingBrowserBinding);
  }

  HttpResult getStatus(String handle, String requestOrigin, String fetchSite,
      String fetchMode, String fetchDest, String csrfToken, String idpOrigin,
      WalletLoginTransactionStore.Binding initiatingBrowserBinding) {
    if (initiatingBrowserBinding == null) return HttpResult.empty(404);
    if (!sameOrigin(idpOrigin, initiatingBrowserBinding.canonicalOrigin())
        || this.idpOrigin != null && !sameOrigin(idpOrigin, this.idpOrigin)) return HttpResult.empty(404);
    if (!"same-origin".equals(fetchSite)
        || !WalletLoginTransportResource.validFetchMetadata(fetchSite, fetchMode, fetchDest)) {
      return HttpResult.empty(403);
    }
    if (requestOrigin != null && !sameOrigin(requestOrigin, initiatingBrowserBinding.canonicalOrigin())) {
      return HttpResult.empty(403);
    }
    var pending = transactions.load(handle, initiatingBrowserBinding);
    var accepted = transactions.getAccepted(handle, initiatingBrowserBinding);
    if (pending.isEmpty() && accepted.isEmpty()) return HttpResult.empty(404);
    WalletLoginTransactionStore.Intent intent = pending.map(
        WalletLoginTransactionStore.PendingTransaction::intent).orElseGet(
        () -> accepted.map(WalletLoginTransactionStore.AcceptedTransaction::intent).orElse(
            WalletLoginTransactionStore.Intent.LOGIN));
    boolean csrfMatches = pending.map(value -> constantTimeEquals(value.csrfToken(), csrfToken)).orElseGet(
        () -> transactions.acceptedCsrfMatches(handle, initiatingBrowserBinding, csrfToken));
    if (!csrfMatches) return HttpResult.empty(403);
    if (accepted.isPresent()) {
      return transactions.callbackGateAvailable(handle, initiatingBrowserBinding)
          ? HttpResult.json(200, Map.of("status", "accepted")) : HttpResult.empty(404);
    }
        return pending.isPresent() ? HttpResult.json(200, Map.of("status", "pending")) : HttpResult.empty(404);
  }

  boolean allowsWalletOrigin(String origin) {
    return walletOrigin != null && sameOrigin(walletOrigin, origin);
  }

  WalletLoginTransactionStore.PendingTransaction pendingTransaction(
      String handle, WalletLoginTransactionStore.Binding binding) {
    return transactionStore.load(handle, binding).orElse(null);
  }

  private boolean validBrowserRequest(String origin, String fetchSite, String fetchMode, String fetchDest) {
    return walletOrigin != null && sameOrigin(walletOrigin, origin)
        && WalletLoginTransportResource.validFetchMetadata(fetchSite, fetchMode, fetchDest);
  }

  private boolean validWalletBrowserRequest(String origin, String fetchSite,
      String fetchMode, String fetchDest) {
    return walletOrigin != null && sameOrigin(walletOrigin, origin)
        && WalletLoginTransportResource.validFetchMetadata(fetchSite, fetchMode, fetchDest);
  }

  private static boolean browserMetadataAbsent(String origin, String site, String mode, String dest) {
    return origin == null && site == null && mode == null && dest == null;
  }

  static boolean sameOrigin(String a, String b) {
    return sameOriginInternal(a, b);
  }

  private static boolean sameOriginInternal(String a, String b) {
    if (a == null || b == null) return false;
    try { return normalizeOrigin(a).equals(normalizeOrigin(b)); }
    catch (IllegalArgumentException ex) { return false; }
  }

  static String normalizeOrigin(String value) {
    java.net.URI uri = java.net.URI.create(value);
    if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
        || uri.getRawAuthority().contains("@") || uri.getRawPath() != null && !uri.getRawPath().isEmpty()
        || uri.getRawQuery() != null || uri.getRawFragment() != null) {
      throw new IllegalArgumentException("wallet origin must be an exact HTTPS origin");
    }
    try {
      int port = uri.getPort() == 443 ? -1 : uri.getPort();
      return new java.net.URI("https", null, uri.getHost().toLowerCase(java.util.Locale.ROOT),
          port, null, null, null).toASCIIString();
    } catch (java.net.URISyntaxException invalidOrigin) {
      throw new IllegalArgumentException("wallet origin is invalid", invalidOrigin);
    }
  }

  private static boolean constantTimeEquals(String expected, String received) {
    if (expected == null || received == null) return false;
    return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
        received.getBytes(StandardCharsets.US_ASCII));
  }
  static String requestCorrelationId(String handle) {
    byte[] digest = sha256(handle.getBytes(StandardCharsets.US_ASCII));
    return java.util.HexFormat.of().formatHex(digest, 0, 16);
  }
  private static byte[] sha256(byte[] bytes) {
    try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
    catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
  }
  private static String hex(byte[] bytes) { return java.util.HexFormat.of().formatHex(bytes); }
  private static Map<String, String> securityHeaders() {
    return Map.of("Cache-Control", "no-store", "Referrer-Policy", "no-referrer",
        "X-Content-Type-Options", "nosniff", "Vary", "Origin",
        "Content-Type", "application/json; charset=utf-8");
  }

  public record HttpResult(int status, Map<String, String> body, Map<String, String> headers) {
    static HttpResult empty(int status) { return new HttpResult(status, Map.of(), securityHeaders()); }
    static HttpResult json(int status, Map<String, String> body) {
      Map<String, String> headers = new HashMap<>(securityHeaders());
      headers.put("Content-Type", "application/json; charset=utf-8");
      return new HttpResult(status, Map.copyOf(body), Map.copyOf(headers));
    }
  }
}
