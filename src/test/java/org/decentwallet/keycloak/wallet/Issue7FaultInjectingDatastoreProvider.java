package org.decentwallet.keycloak.wallet;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserProvider;
import org.keycloak.storage.datastore.DefaultDatastoreProvider;
import org.keycloak.storage.datastore.DefaultDatastoreProviderFactory;

/** Keeps the concrete datastore type required by Keycloak's UserStorageManager local path. */
final class Issue7FaultInjectingDatastoreProvider extends DefaultDatastoreProvider {
  private final String faultMode;
  private UserProvider faultingLocalUsers;

  Issue7FaultInjectingDatastoreProvider(DefaultDatastoreProviderFactory factory,
      KeycloakSession session, String faultMode) {
    super(factory, session);
    this.faultMode = faultMode;
  }

  @Override
  public synchronized UserProvider userLocalStorage() {
    if (faultingLocalUsers == null) {
      faultingLocalUsers = Issue7FaultInjectingUserProviderFactory.decorate(
          super.userLocalStorage(), faultMode);
    }
    return faultingLocalUsers;
  }
}
