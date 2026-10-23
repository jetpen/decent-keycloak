package org.decentwallet.keycloak.wallet;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import org.keycloak.Config;
import org.keycloak.credential.UserCredentialStore;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserProviderFactory;

/** Test-only decorator: injects one exact post-addUser attribute readback failure. */
public final class Issue7FaultInjectingUserProviderFactory implements UserProviderFactory<UserProvider> {
  static final String IDENTITY_ATTRIBUTE = "decent_identity_id";
  private static final String MODE = System.getenv().getOrDefault("ISSUE7_USER_READBACK_FAULT_MODE", "disabled");
  private final String mode;

  public Issue7FaultInjectingUserProviderFactory() {
    this(MODE);
  }

  Issue7FaultInjectingUserProviderFactory(String mode) {
    if (!"disabled".equals(mode) && !"empty".equals(mode) && !"throw".equals(mode) && !"over-cap".equals(mode)) {
      throw new IllegalArgumentException("unsupported Issue #7 user readback fault mode");
    }
    this.mode = mode;
  }

  @Override
  public UserProvider create(KeycloakSession session) {
    System.err.println("ISSUE7_USER_READBACK_PROVIDER: factory selected");
    UserProvider delegate = session.getProvider(UserProvider.class, "jpa");
    if (delegate == null) throw new IllegalStateException("Keycloak local jpa UserProvider unavailable");
    AtomicBoolean armed = new AtomicBoolean();
    AtomicReference<UserModel> created = new AtomicReference<>();
    return (UserProvider) Proxy.newProxyInstance(UserProvider.class.getClassLoader(),
        new Class<?>[] {UserProvider.class, UserCredentialStore.class}, (proxy, method, args) -> {
          UserModel added = created.get();
          if ("searchForUserByUserAttributeStream".equals(method.getName()) && args != null && args.length == 3
              && IDENTITY_ATTRIBUTE.equals(args[1]) && added != null && args[2] instanceof String identity
              && identity.equals(added.getFirstAttribute(IDENTITY_ATTRIBUTE)) && armed.compareAndSet(true, false)) {
            System.err.println("ISSUE7_USER_READBACK_FAULT: post-create exact attribute read intercepted");
            if ("empty".equals(mode)) return Stream.empty();
            if ("throw".equals(mode)) throw new IllegalStateException("issue7 test-only readback unavailable");
            if ("over-cap".equals(mode)) return Stream.generate(() -> added).limit(65);
          }
          try {
            Object result = method.invoke(delegate, args);
            if ("addUser".equals(method.getName()) && result instanceof UserModel user) {
              created.set(user);
              armed.set(true);
            }
            return result;
          } catch (InvocationTargetException failure) {
            throw failure.getCause();
          }
        });
  }

  @Override public void init(Config.Scope config) {}
  @Override public void postInit(KeycloakSessionFactory factory) {}
  @Override public void close() {}
  @Override public String getId() { return "issue7-user-readback-fault"; }
}
