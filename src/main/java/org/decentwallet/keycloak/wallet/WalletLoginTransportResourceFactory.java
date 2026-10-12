package org.decentwallet.keycloak.wallet;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Realm resource factory mounted under /realms/{realm}/decent-wallet-login. */
public final class WalletLoginTransportResourceFactory
    implements RealmResourceProviderFactory {
  public static final String ID = WalletLoginTransportResource.EXTENSION_ID;
  static final String KEY_IDENTITY_RESOLVER = "decent.wallet.identity-resolver";
  static final String KEY_WALLET_ORIGIN = "decent.wallet.browser-origin";
  static final String KEY_IDP_ORIGIN = "decent.wallet.idp-origin";
  static final String KEY_REGISTRY_BOOTSTRAP = "decent.wallet.registry.bootstrap";
  static final String KEY_REGISTRY_CLIENT_PORT = "decent.wallet.registry.client-port";
  static final String KEY_IDENTITY_EXECUTABLE = "decent.wallet.identity.executable";

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    var realm = session.getContext().getRealm();
    WalletLoginIdentityResolver resolver = identityId -> null;
    String bootstrapConfig = realm.getAttribute(KEY_REGISTRY_BOOTSTRAP);
    String clientPortConfig = realm.getAttribute(KEY_REGISTRY_CLIENT_PORT);
    if ((bootstrapConfig == null) != (clientPortConfig == null)) {
      throw new IllegalStateException("Registry bootstrap and client port must be configured together");
    }
    if (bootstrapConfig != null) {
      String executable = realm.getAttribute(KEY_IDENTITY_EXECUTABLE);
      if (executable == null || executable.isBlank()) executable = "decent-identity";
      if (!executable.equals("decent-identity") && !executable.startsWith("/")) {
        throw new IllegalStateException("Identity executable must be a fixed command or absolute path");
      }
      ProcessIdentityResolver currentIdentity = new ProcessIdentityResolver(
          splitBootstrap(bootstrapConfig), parsePort(clientPortConfig), executable);
      resolver = currentIdentity::resolveExact;
    }
    if (resolver == null) resolver = identityId -> null;
    WalletLoginIdentityResolver sharedResolver = resolver;
    String walletOrigin = realm.getAttribute(KEY_WALLET_ORIGIN);
    if (walletOrigin == null || walletOrigin.isBlank()) walletOrigin = null;
    java.net.URI publicBase = session.getContext().getUri().getBaseUri();
    String idpOrigin = canonicalIdpOrigin(publicBase, realm.getAttribute(KEY_IDP_ORIGIN));
    var store = new WalletLoginTransactionStore(session.singleUseObjects(),
        new java.security.SecureRandom(), java.time.Clock.systemUTC());
    WalletLoginAccountResolver accounts = identityId ->
        WalletLoginAccountMapping.findUniqueEnabledUser(session.users(), realm, identityId) != null;
    var resource = new WalletLoginTransportResource();
    resource.configure(session,
        new WalletLoginTransportHandler(store, sharedResolver, walletOrigin, idpOrigin, accounts), idpOrigin);
    return resource;
  }

  static String canonicalIdpOrigin(java.net.URI publicBase, String configuredOrigin) {
    if (publicBase == null || publicBase.getScheme() == null || publicBase.getRawAuthority() == null
        || !"https".equalsIgnoreCase(publicBase.getScheme())) {
      throw new IllegalStateException("Keycloak public base must be HTTPS");
    }
    try {
      String canonical = WalletLoginTransportHandler.normalizeOrigin(
          publicBase.getScheme() + "://" + publicBase.getRawAuthority());
      if (configuredOrigin != null && !configuredOrigin.isBlank()
          && !canonical.equals(WalletLoginTransportHandler.normalizeOrigin(configuredOrigin))) {
        throw new IllegalStateException("configured IdP origin must match Keycloak's trusted public origin");
      }
      return canonical;
    } catch (IllegalArgumentException invalidOrigin) {
      throw new IllegalStateException("Keycloak public origin is invalid", invalidOrigin);
    }
  }

  private static String[] splitBootstrap(String value) {
    if (value == null || value.isBlank()) throw new IllegalStateException("Registry bootstrap peers are not configured");
    return java.util.Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toArray(String[]::new);
  }

  private static int parsePort(String value) {
    try {
      int port = Integer.parseInt(value);
      if (port < 1 || port > 65535) throw new NumberFormatException();
      return port;
    } catch (RuntimeException e) {
      throw new IllegalStateException("Registry client port is not configured");
    }
  }

  @Override public String getId() { return ID; }
  @Override public void init(org.keycloak.Config.Scope config) {}
  @Override public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {}
  @Override public void close() {}
}
