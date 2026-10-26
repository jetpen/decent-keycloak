package org.decentwallet.keycloak.wallet;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.SingleUseObjectProviderFactory;

/** Test-only, one-shot operation-boundary decorator; no concurrency/admission bypass. */
public final class Issue7FaultInjectingSingleUseObjectProviderFactory
    implements SingleUseObjectProviderFactory<SingleUseObjectProvider> {
  private static final String TRANSACTION = "decent-wallet-login-v1:transaction:";
  private static final String ACCEPTED = "decent-wallet-login-v1:accepted:";
  private static final Set<String> MODES = Set.of(
      "consume-loss", "accepted-receipt-write", "accepted-receipt-write-false");
  private final AtomicBoolean injected = new AtomicBoolean();
  private final Path marker;
  private final String mode;

  public Issue7FaultInjectingSingleUseObjectProviderFactory() {
    this(System.getenv().getOrDefault("ISSUE7_TEST_FAULT_MODE", "consume-loss"));
  }

  Issue7FaultInjectingSingleUseObjectProviderFactory(String mode) {
    this(mode, Path.of("/tmp/issue7-provider-fault-injected"));
  }

  Issue7FaultInjectingSingleUseObjectProviderFactory(String mode, Path marker) {
    if (!MODES.contains(mode)) throw new IllegalArgumentException("unsupported Issue7 test fault mode");
    this.mode = mode;
    this.marker = marker;
  }

  @Override
  public SingleUseObjectProvider create(KeycloakSession session) {
    SingleUseObjectProvider delegate = session.getProvider(SingleUseObjectProvider.class, "infinispan");
    if (delegate == null) throw new IllegalStateException("infinispan single-use provider unavailable");
    System.err.println("ISSUE7_TEST_PROVIDER: factory create invoked");
    return new SingleUseObjectProvider() {
      @Override
      public void put(String key, long lifespan, Map<String, String> notes) {
        delegate.put(key, lifespan, notes);
      }
      @Override
      public Map<String, String> get(String key) { return delegate.get(key); }
      @Override
      public Map<String, String> remove(String key) {
        Map<String, String> removed = delegate.remove(key);
        if (removed != null && mode.equals("consume-loss") && key.startsWith(TRANSACTION)) {
          String requestId = requestCorrelationId(key.substring(TRANSACTION.length()));
          System.err.println("ISSUE7_TEST_PROVIDER_OPERATION: operation=transaction_remove request=" + requestId);
          if (claim()) {
            System.err.println("ISSUE7_TEST_FAULT: pending consume committed then threw request=" + requestId);
            throw new IllegalStateException("test-only post-consume fault");
          }
        }
        return removed;
      }
      @Override
      public boolean replace(String key, Map<String, String> notes) {
        boolean acceptance = key.startsWith(ACCEPTED) && "accepted".equals(notes.get("status"));
        String requestId = acceptance ? requestCorrelationId(key.substring(ACCEPTED.length())) : null;
        if (acceptance) System.err.println(
            "ISSUE7_TEST_PROVIDER_OPERATION: operation=accepted_replace request=" + requestId);
        if (acceptance && mode.equals("accepted-receipt-write-false") && claim()) {
          System.err.println("ISSUE7_TEST_FAULT: accepted receipt write returned false before commit request=" + requestId);
          return false;
        }
        boolean committed = delegate.replace(key, notes);
        if (committed && acceptance && mode.equals("accepted-receipt-write") && claim()) {
          System.err.println("ISSUE7_TEST_FAULT: accepted receipt write committed then threw request=" + requestId);
          throw new IllegalStateException("test-only accepted receipt postwrite fault");
        }
        return committed;
      }
      @Override
      public boolean putIfAbsent(String key, long lifespan) { return delegate.putIfAbsent(key, lifespan); }
      @Override
      public boolean contains(String key) { return delegate.contains(key); }
      @Override
      public void close() { /* Session owns delegate lifecycle. */ }
    };
  }

  private static String requestCorrelationId(String handle) {
    return WalletLoginTransportHandler.requestCorrelationId(handle);
  }

  private boolean claim() {
    if (injected.get()) return false;
    try {
      Files.createFile(marker);
      injected.set(true);
      return true;
    } catch (FileAlreadyExistsException alreadyInjected) {
      injected.set(true);
      return false;
    } catch (IOException failure) {
      throw new IllegalStateException("test fault marker unavailable", failure);
    }
  }

  @Override public void init(Config.Scope config) {}
  @Override public void postInit(KeycloakSessionFactory factory) {}
  @Override public void close() {}
  @Override public String getId() { return "issue7-fault-injection"; }
}
