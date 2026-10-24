package org.decentwallet.keycloak.issue6test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

class Issue6PostConsumeCallbackGateFailureProviderFactoryTest {
  @Test
  void selectionWitnessUsesTheStorageKeyHandleDigestPrefix() {
    KeycloakSession session = mock(KeycloakSession.class);
    SingleUseObjectProvider delegate = mock(SingleUseObjectProvider.class);
    when(session.getProvider(SingleUseObjectProvider.class, "infinispan")).thenReturn(delegate);
    when(delegate.putIfAbsent(anyString(), anyLong())).thenReturn(true);
    SingleUseObjectProvider decorated = new Issue6PostConsumeCallbackGateFailureProviderFactory().create(session);
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
        + "issue6-postconsume-callback-gate-failure operation=transaction_put_if_absent request="
        + digest.substring(0, 32)));
    org.junit.jupiter.api.Assertions.assertFalse(marker.contains(digest));
  }

  @Test
  void commitsOnlyExactCallbackGatePutIfAbsentBeforeThrowingOnce() {
    KeycloakSession session = mock(KeycloakSession.class);
    SingleUseObjectProvider delegate = mock(SingleUseObjectProvider.class);
    Set<String> committedKeys = new HashSet<>();
    when(session.getProvider(SingleUseObjectProvider.class, "infinispan")).thenReturn(delegate);
    when(delegate.putIfAbsent(anyString(), anyLong())).thenAnswer(invocation ->
        committedKeys.add(invocation.getArgument(0)));
    SingleUseObjectProvider decorated = new Issue6PostConsumeCallbackGateFailureProviderFactory().create(session);

    assertDoesNotThrow(() -> decorated.putIfAbsent("ordinary-key", 60));
    assertDoesNotThrow(() -> decorated.putIfAbsent(
        "decent-wallet-login-v1:accepted:receipt", 60));
    String callbackKey = "decent-wallet-login-v1:callback:opaque";
    assertThrows(IllegalStateException.class, () -> decorated.putIfAbsent(callbackKey, 60));
    assertEquals(Set.of("ordinary-key", "decent-wallet-login-v1:accepted:receipt", callbackKey), committedKeys,
        "the exact callback gate must be in delegate state before the test fault is thrown");
    assertDoesNotThrow(() -> decorated.putIfAbsent("decent-wallet-login-v1:callback:another", 60));
    verify(delegate).putIfAbsent(callbackKey, 60);
  }
}
