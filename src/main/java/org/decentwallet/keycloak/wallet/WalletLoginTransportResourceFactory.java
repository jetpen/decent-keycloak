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
  static final String KEY_SITE_LABEL = "decent.wallet.site-name";
  static final String KEY_TRUSTED_WALLET_ORIGINS = "decent.wallet.trusted-origins";

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
    boolean acceptSignup = realm.isRegistrationAllowed();
    String walletOrigin = realm.getAttribute(KEY_WALLET_ORIGIN);
    if (walletOrigin != null && walletOrigin.isBlank()) walletOrigin = null;
    final String configuredWalletOrigin = walletOrigin;
    String trustedOrigins = realm.getAttribute(KEY_TRUSTED_WALLET_ORIGINS);
    if (trustedOrigins != null && !trustedOrigins.isBlank()) {
      boolean matched = java.util.Arrays.stream(trustedOrigins.split(","))
          .map(String::trim)
          .anyMatch(candidate -> WalletLoginTransportHandler.sameOrigin(candidate, configuredWalletOrigin));
      if (!matched) throw new IllegalStateException("wallet origin is not in the exact trusted-origin allowlist");
    }
    java.net.URI publicBase = session.getContext().getUri().getBaseUri();
    String idpOrigin = canonicalIdpOrigin(publicBase, realm.getAttribute(KEY_IDP_ORIGIN));
    var store = new WalletLoginTransactionStore(session.singleUseObjects(),
        new java.security.SecureRandom(), java.time.Clock.systemUTC());
    WalletLoginAccountResolver accounts = new WalletLoginAccountResolver() {
      @Override public boolean hasUniqueEnabledUser(String identityId) {
        return WalletLoginAccountMapping.hasUniqueEnabledMapping(session.users(), realm, identityId);
      }
      @Override public boolean hasUniqueMappedUserIncludingDisabled(String identityId) {
        return WalletLoginAccountMapping.hasUniqueMappingIncludingDisabled(session.users(), realm, identityId);
      }
      @Override public org.keycloak.models.UserModel ensureEnabledUser(String identityId) {
        return WalletLoginAccountMapping.ensureEnabledUser(session.users(), realm, identityId, true);
      }
    };
    var resource = new WalletLoginTransportResource();
    resource.configure(session,
        new WalletLoginTransportHandler(store, sharedResolver, walletOrigin, idpOrigin, accounts,
            acceptSignup, store), idpOrigin, acceptSignup);
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
