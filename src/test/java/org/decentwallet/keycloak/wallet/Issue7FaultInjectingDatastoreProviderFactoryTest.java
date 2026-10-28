package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.provider.ProviderEventListener;
import org.keycloak.storage.DatastoreProvider;
import org.keycloak.storage.UserStorageEventListener;
import org.keycloak.storage.datastore.DefaultDatastoreProvider;

class Issue7FaultInjectingDatastoreProviderFactoryTest {
  @Test
  void factoryRegistersTheDefaultUserStorageLifecycleListeners() {
    Issue7FaultInjectingDatastoreProviderFactory factory =
        new Issue7FaultInjectingDatastoreProviderFactory("disabled");
    KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
    ArgumentCaptor<ProviderEventListener> listeners = ArgumentCaptor.forClass(ProviderEventListener.class);

    factory.postInit(sessionFactory);

    verify(sessionFactory, times(2)).register(listeners.capture());
    assertTrue(listeners.getAllValues().stream().anyMatch(listener -> listener == factory));
    assertTrue(listeners.getAllValues().stream().anyMatch(UserStorageEventListener.class::isInstance));
  }

  @Test
  void datastoreProviderWrapsTheLocalUserProviderAndKeepsKeycloakConcreteType() {
    KeycloakSession session = mock(KeycloakSession.class);
    UserProvider localUsers = mock(UserProvider.class);
    RealmModel realm = mock(RealmModel.class);
    UserModel created = mock(UserModel.class);
    when(session.getProvider(UserProvider.class)).thenReturn(localUsers);
    when(localUsers.addUser(realm, "probe-user")).thenReturn(created);
    when(created.getFirstAttribute("decent_identity_id")).thenReturn("probe-identity");
    when(localUsers.searchForUserByUserAttributeStream(realm, "decent_identity_id", "probe-identity"))
        .thenReturn(Stream.of(created));

    DatastoreProvider provider = new Issue7FaultInjectingDatastoreProviderFactory("disabled").create(session);

    DefaultDatastoreProvider keycloakDatastore = assertInstanceOf(DefaultDatastoreProvider.class, provider);
    UserProvider wrappedUsers = keycloakDatastore.userLocalStorage();
    assertNotSame(localUsers, wrappedUsers);
    assertSame(created, wrappedUsers.addUser(realm, "probe-user"));
    assertEquals(1, wrappedUsers.searchForUserByUserAttributeStream(
        realm, "decent_identity_id", "probe-identity").count());
    verify(localUsers).addUser(realm, "probe-user");
    verify(localUsers).searchForUserByUserAttributeStream(realm, "decent_identity_id", "probe-identity");
  }
}
