package org.decentwallet.keycloak.wallet;

/** Request-local correlation bridge for synchronous provider interception. */
final class WalletRequestCorrelation {
  private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

  private WalletRequestCorrelation() {}

  static String current() {
    return CURRENT.get();
  }

  static boolean isValidRequestId(String requestId) {
    return requestId != null && requestId.matches("[0-9a-f]{32}");
  }

  static Scope open(String requestId) {
    String previous = CURRENT.get();
    CURRENT.set(requestId);
    return () -> {
      if (previous == null) CURRENT.remove();
      else CURRENT.set(previous);
    };
  }

  @FunctionalInterface
  interface Scope extends AutoCloseable {
    @Override void close();
  }
}