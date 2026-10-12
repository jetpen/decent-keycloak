package org.decentwallet.keycloak.wallet;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

final class WalletChallengeUserMappingTest {
  @Test
  void actionMapsExactIdentityAttributeToOpaqueLocalUserId() {
    String identityId = "mailto:alice@example.org";
    UserModel user = mock(UserModel.class);
    when(user.isEnabled()).thenReturn(true);
    when(user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    Harness harness = arrange(identityId, Stream.of(user));

    new WalletChallengeAuthenticator(() -> harness.store()).action(harness.context());

    verify(harness.users()).searchForUserByUserAttributeStream(harness.realm(),
        WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE, identityId);
    verify(harness.users(), never()).getUserById(harness.realm(), identityId);
    verify(harness.auth()).setAuthenticatedUser(user);
    verify(harness.context()).success();
  }

  @Test
  void actionDoesNotConsumeCallbackGateWhenSettingUserFails() {
    String identityId = "mailto:alice@example.org";
    UserModel user = matchingUser(identityId);
    Harness harness = arrange(identityId, Stream.of(user));
    org.mockito.Mockito.doThrow(new IllegalStateException("test session failure"))
        .when(harness.auth()).setAuthenticatedUser(user);

    new WalletChallengeAuthenticator(() -> harness.store()).action(harness.context());

    verify(harness.store()).getAccepted(anyString(), any());
    verify(harness.store(), never()).takeAccepted(anyString(), any());
    verify(harness.context()).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
  }

  @Test
  void actionFailsClosedWhenMultipleLocalUsersMatchOneIdentity() {
    String identityId = "mailto:alice@example.org";
    UserModel first = matchingUser(identityId);
    UserModel second = matchingUser(identityId);
    Harness harness = arrange(identityId, Stream.of(first, second));

    new WalletChallengeAuthenticator(() -> harness.store()).action(harness.context());

    verify(harness.auth(), never()).setAuthenticatedUser(any());
    verify(harness.context()).failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
    verify(harness.context(), never()).success();
  }

  private static UserModel matchingUser(String identityId) {
    UserModel user = mock(UserModel.class);
    when(user.isEnabled()).thenReturn(true);
    when(user.getFirstAttribute(WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE)).thenReturn(identityId);
    return user;
  }

  private static Harness arrange(String identityId, Stream<UserModel> candidates) {
    var store = mock(WalletLoginTransactionStore.class);
    var receipt = new WalletLoginTransactionStore.AcceptedTransaction(identityId,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "proof-digest", binding());
    when(store.getAccepted(anyString(), any())).thenReturn(Optional.of(receipt));
    when(store.takeAccepted(anyString(), any())).thenReturn(Optional.of(receipt));

    var context = mock(AuthenticationFlowContext.class);
    var session = mock(KeycloakSession.class);
    var auth = mock(AuthenticationSessionModel.class);
    var parent = mock(RootAuthenticationSessionModel.class);
    var client = mock(ClientModel.class);
    var realm = mock(RealmModel.class);
    var users = mock(UserProvider.class);
    when(context.getAuthenticationSession()).thenReturn(auth);
    when(context.getSession()).thenReturn(session);
    when(context.getRealm()).thenReturn(realm);
    when(realm.getId()).thenReturn("realm-id");
    when(session.users()).thenReturn(users);
    when(auth.getClient()).thenReturn(client);
    when(auth.getParentSession()).thenReturn(parent);
    when(parent.getId()).thenReturn("root-session-id");
    when(client.getId()).thenReturn("client-id");
    when(auth.getTabId()).thenReturn("tab-id");
    when(auth.getRedirectUri()).thenReturn("https://site.example/callback");
    when(auth.getAuthNote(anyString())).thenAnswer(invocation -> switch (invocation.getArgument(0, String.class)) {
      case "decent.wallet.handle" -> "A".repeat(43);
      case "decent.wallet.origin" -> "https://idp.example";
      default -> null;
    });
    when(users.searchForUserByUserAttributeStream(realm, WalletChallengeAuthenticator.IDENTITY_ATTRIBUTE,
        identityId)).thenReturn(candidates);
    return new Harness(store, context, auth, realm, users);
  }

  private static WalletLoginTransactionStore.Binding binding() {
    return new WalletLoginTransactionStore.Binding("realm-id", "client-id", "root-session-id",
        "tab-id", "https://site.example/callback", "https://idp.example");
  }

  private record Harness(WalletLoginTransactionStore store, AuthenticationFlowContext context,
      AuthenticationSessionModel auth, RealmModel realm, UserProvider users) {}
}
