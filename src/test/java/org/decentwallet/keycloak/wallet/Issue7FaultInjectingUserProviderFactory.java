package org.decentwallet.keycloak.wallet;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;
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
    System.err.println("ISSUE7_USER_READBACK_PROVIDER: factory create invoked");
    System.err.println("ISSUE7_USER_READBACK_PROVIDER: fault mode=" + mode);
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
            System.err.println("ISSUE7_USER_READBACK_OPERATION: post_create_exact_attribute_read");
            System.err.println("ISSUE7_USER_READBACK_FAULT: post-create exact attribute read intercepted");
            if ("empty".equals(mode)) {
              System.err.println("ISSUE7_USER_READBACK_OUTCOME: empty");
              return Stream.empty();
            }
            if ("throw".equals(mode)) {
              System.err.println("ISSUE7_USER_READBACK_OUTCOME: throw");
              throw new IllegalStateException("issue7 test-only readback unavailable");
            }
            if ("over-cap".equals(mode)) {
              System.err.println("ISSUE7_USER_READBACK_OUTCOME: over-cap");
              return IntStream.range(0, 65).mapToObj(index -> syntheticCandidate(added, index));
            }
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

  private static UserModel syntheticCandidate(UserModel created, int ordinal) {
    return (UserModel) Proxy.newProxyInstance(UserModel.class.getClassLoader(),
        new Class<?>[] {UserModel.class}, (proxy, method, args) -> {
          if ("getId".equals(method.getName()) && method.getParameterCount() == 0) {
            return "issue7-over-cap-candidate-" + ordinal;
          }
          try {
            return method.invoke(created, args);
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
