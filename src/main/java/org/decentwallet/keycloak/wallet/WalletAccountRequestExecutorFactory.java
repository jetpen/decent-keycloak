package org.decentwallet.keycloak.wallet;

import java.util.List;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

/** Registers the signed account-action client-policy executor with Keycloak. */
public final class WalletAccountRequestExecutorFactory implements ClientPolicyExecutorProviderFactory {
  public WalletAccountRequestExecutorFactory() { }

  @Override public WalletAccountRequestExecutor create(org.keycloak.models.KeycloakSession session) {
    return new WalletAccountRequestExecutor(session);
  }
  @Override public void init(org.keycloak.Config.Scope config) { }
  @Override public void postInit(org.keycloak.models.KeycloakSessionFactory factory) { }
  @Override public void close() { }
  @Override public String getId() { return WalletAccountRequestExecutor.PROVIDER_ID; }
  @Override public String getHelpText() {
    return "Requires a signed ES256 Request Object and binds its one-use account action to the AuthenticationSession.";
  }
  @Override public List<org.keycloak.provider.ProviderConfigProperty> getConfigProperties() {
    return List.of(new org.keycloak.provider.ProviderConfigProperty("enabled", "Enabled",
        "Enable strict account Request Object validation for this client policy.",
        org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE, true));
  }
}
