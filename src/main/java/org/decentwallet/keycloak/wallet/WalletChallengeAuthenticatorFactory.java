package org.decentwallet.keycloak.wallet;

import java.security.SecureRandom;
import java.time.Clock;
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
  @Override public Authenticator create(KeycloakSession session) {
    return new WalletChallengeAuthenticator(() -> new WalletLoginTransactionStore(
        session.singleUseObjects(), new SecureRandom(), Clock.systemUTC()));
  }
  @Override public String getId() { return ID; }
  @Override public String getDisplayType() { return "Decent wallet challenge (development spike)"; }
  @Override public String getReferenceCategory() { return "decent-wallet"; }
  @Override public boolean isConfigurable() { return true; }
  @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED};
  }
  @Override public boolean isUserSetupAllowed() { return false; }
  @Override public String getHelpText() { return "Starts the provider-hosted decent-wallet-login-v1 flow. Configure trusted-origins and the realm's decent.wallet.* transport/Identity settings."; }
  @Override public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigProperty origins = new ProviderConfigProperty();
    origins.setName("trusted-origins");
    origins.setLabel("Trusted HTTPS origins");
    origins.setType(ProviderConfigProperty.TEXT_TYPE);
    origins.setHelpText("Comma-separated exact HTTPS origins. One must match the Keycloak public base origin.");
    return List.of(origins);
  }
  @Override public void init(org.keycloak.Config.Scope config) {}
  @Override public void postInit(KeycloakSessionFactory factory) {}
  @Override public void close() {}
}
