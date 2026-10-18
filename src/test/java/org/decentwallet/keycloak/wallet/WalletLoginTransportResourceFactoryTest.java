package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.KeycloakUriInfo;

final class WalletLoginTransportResourceFactoryTest {
  @Test
  void existingBrowserOriginSettingDoesNotNeedADuplicateTrustedOriginsAttribute() {
    var session = mock(KeycloakSession.class);
    var context = mock(KeycloakContext.class);
    var uriInfo = mock(KeycloakUriInfo.class);
    var realm = mock(RealmModel.class);
    when(session.getContext()).thenReturn(context);
    when(session.singleUseObjects()).thenReturn(mock(SingleUseObjectProvider.class));
    when(context.getRealm()).thenReturn(realm);
    when(context.getUri()).thenReturn(uriInfo);
    when(uriInfo.getBaseUri()).thenReturn(URI.create("https://idp.example/auth/"));
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_WALLET_ORIGIN))
        .thenReturn("https://wallet.example");

    org.junit.jupiter.api.Assertions.assertDoesNotThrow(
        () -> new WalletLoginTransportResourceFactory().create(session));
  }

  @Test
  void resolverExecutableDefaultsToTheBundledRuntimePathWhenRegistryIsConfigured() {
    var session = mock(KeycloakSession.class);
    var context = mock(KeycloakContext.class);
    var uriInfo = mock(KeycloakUriInfo.class);
    var realm = mock(RealmModel.class);
    when(session.getContext()).thenReturn(context);
    when(session.singleUseObjects()).thenReturn(mock(SingleUseObjectProvider.class));
    when(context.getRealm()).thenReturn(realm);
    when(context.getUri()).thenReturn(uriInfo);
    when(uriInfo.getBaseUri()).thenReturn(URI.create("https://idp.example/auth/"));
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_REGISTRY_BOOTSTRAP))
        .thenReturn("/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWBJHhhdqp4zbtGbCX6VyE7hC2ch5uaEvxfwkmSbfo2f3X");
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_REGISTRY_CLIENT_PORT))
        .thenReturn("9001");
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_IDENTITY_EXECUTABLE))
        .thenReturn(null);

    new WalletLoginTransportResourceFactory().create(session);
  }

  @Test
  void canonicalizesDefaultHttpsPortForFactoryAndAuthenticator() {
    assertEquals("https://idp.example", WalletLoginTransportResourceFactory.canonicalIdpOrigin(
        URI.create("https://idp.example/auth/"), "https://idp.example:443"));
    assertEquals("https://idp.example", WalletLoginTransportResourceFactory.canonicalIdpOrigin(
        URI.create("https://idp.example:443/auth/"), "https://idp.example"));
  }

  @Test
  void rejectsIdpOriginOverrideThatConflictsWithTrustedKeycloakBase() {
    var session = mock(KeycloakSession.class);
    var context = mock(KeycloakContext.class);
    var uriInfo = mock(KeycloakUriInfo.class);
    var realm = mock(RealmModel.class);
    when(session.getContext()).thenReturn(context);
    when(session.singleUseObjects()).thenReturn(mock(SingleUseObjectProvider.class));
    when(context.getRealm()).thenReturn(realm);
    when(context.getUri()).thenReturn(uriInfo);
    when(uriInfo.getBaseUri()).thenReturn(URI.create("https://idp.example/auth/"));
    when(realm.getAttribute(WalletLoginTransportResourceFactory.KEY_IDP_ORIGIN))
        .thenReturn("https://alias.example");

    assertThrows(IllegalStateException.class,
        () -> new WalletLoginTransportResourceFactory().create(session));
  }
}
