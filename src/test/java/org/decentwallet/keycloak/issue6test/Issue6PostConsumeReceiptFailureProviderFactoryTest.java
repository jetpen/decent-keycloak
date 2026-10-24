package org.decentwallet.keycloak.issue6test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

class Issue6PostConsumeReceiptFailureProviderFactoryTest {
  @Test
  void selectionWitnessUsesTheStorageKeyHandleDigestPrefix() throws Exception {
    KeycloakSession session = mock(KeycloakSession.class);
    SingleUseObjectProvider delegate = mock(SingleUseObjectProvider.class);
    when(session.getProvider(SingleUseObjectProvider.class, "infinispan")).thenReturn(delegate);
    when(delegate.putIfAbsent(anyString(), anyLong())).thenReturn(true);
    SingleUseObjectProvider decorated = new Issue6PostConsumeReceiptFailureProviderFactory().create(session);
    String digest = "0123456789abcdef0123456789abcdef" + "fedcba9876543210fedcba9876543210";
    String key = "decent-wallet-login-v1:transaction:" + digest;
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    PrintStream previous = System.err;
    try (PrintStream stream = new PrintStream(captured, true, StandardCharsets.UTF_8)) {
      System.setErr(stream);
      assertTrue(decorated.putIfAbsent(key, 300));
    } finally {
      System.setErr(previous);
    }
    String marker = captured.toString(StandardCharsets.UTF_8);
    assertTrue(marker.contains("ISSUE6_TEST_PROVIDER_SELECTED: provider="
        + "issue6-postconsume-receipt-failure operation=transaction_put_if_absent request="
        + digest.substring(0, 32)));
    org.junit.jupiter.api.Assertions.assertFalse(marker.contains(digest));
  }

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
