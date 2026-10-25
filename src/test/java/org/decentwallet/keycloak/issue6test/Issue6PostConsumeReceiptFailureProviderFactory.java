package org.decentwallet.keycloak.issue6test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.SingleUseObjectProviderFactory;

/** Test-image-only decorator for one accepted-receipt post-commit failure. */
public final class Issue6PostConsumeReceiptFailureProviderFactory
    implements SingleUseObjectProviderFactory<SingleUseObjectProvider> {
  private static final String ACCEPTED_PREFIX = "decent-wallet-login-v1:accepted:";
  private static final String HANDLE_PREFIX = "decent-wallet-login-v1:transaction:";
  private static final AtomicBoolean SELECTION_WITNESSED = new AtomicBoolean();
  private static final AtomicBoolean INJECTED = new AtomicBoolean();

  @Override
  public SingleUseObjectProvider create(KeycloakSession session) {
    System.err.println("ISSUE6_TEST_PROVIDER_FACTORY_CREATED: provider=issue6-postconsume-receipt-failure");
    SingleUseObjectProvider delegate = session.getProvider(SingleUseObjectProvider.class, "infinispan");
    if (delegate == null) {
      throw new IllegalStateException("Keycloak infinispan single-use provider unavailable");
    }
    return new SingleUseObjectProvider() {
      @Override public void put(String key, long lifespanSeconds, Map<String, String> notes) {
        delegate.put(key, lifespanSeconds, notes);
      }
      @Override public Map<String, String> get(String key) { return delegate.get(key); }
      @Override public Map<String, String> remove(String key) { return delegate.remove(key); }
      @Override public boolean replace(String key, Map<String, String> notes) {
        boolean committed = delegate.replace(key, notes);
        if (committed && key.startsWith(ACCEPTED_PREFIX) && notes != null
            && "accepted".equals(notes.get("status"))
            && INJECTED.compareAndSet(false, true)) {
          System.err.println("ISSUE6_TEST_FAULT: accepted receipt delegate write committed; test decorator threw");
          throw new IllegalStateException("issue6 test-only post-consume receipt fault");
        }
        return committed;
      }
      @Override public boolean putIfAbsent(String key, long lifespanSeconds) {
        boolean committed = delegate.putIfAbsent(key, lifespanSeconds);
        if (key.startsWith(HANDLE_PREFIX)) {
          String requestId = requestId(key);
          if (requestId != null && SELECTION_WITNESSED.compareAndSet(false, true)) {
            System.err.println("ISSUE6_TEST_PROVIDER_SELECTED: provider=issue6-postconsume-receipt-failure "
                + "operation=transaction_put_if_absent request=" + requestId);
          }
        }
        return committed;
      }
      @Override public boolean contains(String key) { return delegate.contains(key); }
      @Override public void close() { /* The session owns the delegate lifecycle. */ }
    };
  }

  private static String requestId(String key) {
    String storageDigest = key.substring(HANDLE_PREFIX.length());
    if (storageDigest.length() != 64) return null;
    for (int i = 0; i < storageDigest.length(); i++) {
      char value = storageDigest.charAt(i);
      if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'))) return null;
    }
    return storageDigest.substring(0, 32);
  }

  @Override public void init(Config.Scope config) {}
  @Override public void postInit(KeycloakSessionFactory factory) {}
  @Override public void close() {}
  @Override public String getId() { return "issue6-postconsume-receipt-failure"; }
}
