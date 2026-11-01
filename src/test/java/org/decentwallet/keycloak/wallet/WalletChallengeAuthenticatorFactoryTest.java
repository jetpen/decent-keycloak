package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

final class WalletChallengeAuthenticatorFactoryTest {
  @Test
  void factoryReportsTheExactProviderInstanceUsedByTheAuthenticatorStore() {
    var session = mock(KeycloakSession.class);
    var provider = mock(SingleUseObjectProvider.class, org.mockito.Mockito.withSettings()
        .name("infinispan-provider"));
    when(session.singleUseObjects()).thenReturn(provider);

    new WalletChallengeAuthenticatorFactory().create(session);

    assertTrue(WalletLoginTransactionStore.providerIdForClassName(provider.getClass().getName())
        == WalletLoginTransactionStore.SingleUseObjectProviderId.UNKNOWN
        || provider.getClass().getName().equals(
            "org.keycloak.models.sessions.infinispan.InfinispanSingleUseObjectProvider"));
  }

  @Test
  void factoryExposesOneRequiredLoginExecutionAndStableProviderId() {
    var factory = new WalletChallengeAuthenticatorFactory();

    assertTrue(factory.getRequirementChoices().length == 1);
    assertTrue(factory.getRequirementChoices()[0] == org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED);
    assertTrue("decent-wallet-challenge".equals(factory.getId()));
  }
}
