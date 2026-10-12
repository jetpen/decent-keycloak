package org.decent.keycloak.wallet;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

final class WalletChallengeAuthenticatorTest {
  @Test
  void authenticateFailsClosedUntilVerifierIsImplemented() {
    var authenticator = new WalletChallengeAuthenticator();
    var context = mock(AuthenticationFlowContext.class);

    authenticator.authenticate(context);

    verify(context).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
  }

  @Test
  void callbackActionFailsClosedUntilVerifierIsImplemented() {
    var authenticator = new WalletChallengeAuthenticator();
    var context = mock(AuthenticationFlowContext.class);

    authenticator.action(context);

    verify(context).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
  }

  @Test
  void providerHasNoUserSetupFallback() {
    var authenticator = new WalletChallengeAuthenticator();

    assertEquals(false, authenticator.requiresUser());
    assertEquals(false, authenticator.configuredFor(null, null, null));
  }
}
