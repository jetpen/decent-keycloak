package org.decent.keycloak.wallet;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Fail-closed entry point for the wallet browser-login experiment.
 *
 * No challenge transcript, wallet transport, Registry resolver, or atomic replay
 * store is implemented yet. Until those components and their live tests exist,
 * this authenticator must not establish an authenticated Keycloak session.
 */
public final class WalletChallengeAuthenticator implements Authenticator {
  static final String UNIMPLEMENTED_MESSAGE = "Wallet challenge verification is not configured";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
  }

  @Override
  public boolean requiresUser() {
    return false;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return false;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // User enrollment cannot replace a fresh wallet challenge.
  }

  @Override
  public void close() {}
}
