package org.decentwallet.keycloak.issue6test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

class Issue6PostConsumeReceiptFailureProviderFactoryTest {
  @Test
  void delegatesAndThrowsOnceOnlyAfterAcceptedReceiptWasCommitted() {
    KeycloakSession session = mock(KeycloakSession.class);
    SingleUseObjectProvider delegate = mock(SingleUseObjectProvider.class);
    Map<String, Map<String, String>> committedReceipts = new HashMap<>();
    when(session.getProvider(SingleUseObjectProvider.class, "infinispan")).thenReturn(delegate);
    when(delegate.replace(anyString(), anyMap())).thenAnswer(invocation -> {
      committedReceipts.put(invocation.getArgument(0), invocation.getArgument(1));
      return true;
    });
    SingleUseObjectProvider decorated = new Issue6PostConsumeReceiptFailureProviderFactory().create(session);

    Map<String, String> accepted = Map.of("status", "accepted");
    assertDoesNotThrow(() -> decorated.replace("ordinary-key", accepted));
    assertDoesNotThrow(() -> decorated.replace(
        "decent-wallet-login-v1:accepted:pending", Map.of("status", "pending")));

    String acceptedReceiptKey = "decent-wallet-login-v1:accepted:opaque";
    assertThrows(IllegalStateException.class, () -> decorated.replace(acceptedReceiptKey, accepted));
    assertEquals(accepted, committedReceipts.get(acceptedReceiptKey),
        "the delegate write must be committed before the decorator throws");
    assertDoesNotThrow(() -> decorated.replace(
        "decent-wallet-login-v1:accepted:another", accepted));
    decorated.put("ordinary-key", 10, Map.of("status", "ordinary"));
    verify(delegate).put("ordinary-key", 10, Map.of("status", "ordinary"));
    verify(delegate, times(4)).replace(anyString(), anyMap());
  }
}
