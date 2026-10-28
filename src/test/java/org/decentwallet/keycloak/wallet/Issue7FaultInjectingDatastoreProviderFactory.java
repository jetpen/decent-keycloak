package org.decentwallet.keycloak.wallet;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.storage.DatastoreProvider;
import org.keycloak.storage.datastore.DefaultDatastoreProviderFactory;

/** Test-only datastore factory that injects faults into the local UserProvider seam. */
public final class Issue7FaultInjectingDatastoreProviderFactory extends DefaultDatastoreProviderFactory {
  static final String PROVIDER_ID = Issue7FaultInjectingUserProviderFactory.PROVIDER_ID;
  private static final String MODE = System.getenv().getOrDefault("ISSUE7_USER_READBACK_FAULT_MODE", "disabled");
  private final String mode;

  public Issue7FaultInjectingDatastoreProviderFactory() {
    this(MODE);
  }

  Issue7FaultInjectingDatastoreProviderFactory(String mode) {
    Issue7FaultInjectingUserProviderFactory.validateMode(mode);
    this.mode = mode;
  }

  @Override
  public DatastoreProvider create(KeycloakSession session) {
    System.err.println("ISSUE7_USER_READBACK_PROVIDER: factory create invoked");
    System.err.println("ISSUE7_USER_READBACK_PROVIDER: fault mode=" + mode);
    return new Issue7FaultInjectingDatastoreProvider(this, session, mode);
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    super.postInit(factory);
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
