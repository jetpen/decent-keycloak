package org.decent.keycloak.wallet;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

final class WalletChallengeAuthenticatorFactoryTest {
  @Test
  void factoryExposesOneRequiredLoginExecutionAndStableProviderId() {
    var factory = new WalletChallengeAuthenticatorFactory();

    assertTrue(factory.getRequirementChoices().length == 1);
    assertTrue(factory.getRequirementChoices()[0] == org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED);
    assertTrue("decent-wallet-challenge".equals(factory.getId()));
  }
}
