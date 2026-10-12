package org.decent.keycloak.wallet;

import java.util.List;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
/** SPI registration and required-flow metadata for the development authenticator. */
public final class WalletChallengeAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {
  public static final String ID = "decent-wallet-challenge";
  private static final Authenticator AUTHENTICATOR = new WalletChallengeAuthenticator();
  @Override public Authenticator create(KeycloakSession session) { return AUTHENTICATOR; }
  @Override public String getId() { return ID; }
  @Override public String getDisplayType() { return "Decent wallet challenge (development spike)"; }
  @Override public String getReferenceCategory() { return "decent-wallet"; }
  @Override public boolean isConfigurable() { return false; }
  @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED};
  }
  @Override public boolean isUserSetupAllowed() { return false; }
  @Override public String getHelpText() { return "Development-only request for a fresh wallet challenge; no wallet verifier is wired yet."; }
  @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
  @Override public void init(org.keycloak.Config.Scope config) {}
  @Override public void postInit(KeycloakSessionFactory factory) {}
  @Override public void close() {}
}
