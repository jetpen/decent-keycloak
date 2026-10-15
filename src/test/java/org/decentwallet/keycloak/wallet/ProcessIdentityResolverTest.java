package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

final class ProcessIdentityResolverTest {
  @Test
  void extractsKnownDiagnosticsAroundOneBalancedIdentityObject() {
    String identity = "mailto:alice@example.org";
    String key = "11".repeat(32);
    String json = "{\n  \"identifier\": \"" + identity
        + "\",\n  \"owner_name_hex\": \"" + java.util.HexFormat.of().formatHex(
            identity.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        + "\",\n  \"owner_public_key_hex\": \"" + key
        + "\",\n  \"seq\": 2\n}";
    String statusLines = "Dialing /ip4/127.0.0.1/tcp/9000\nConnected to /ip4/127.0.0.1/tcp/9000/p2p/peer\n";
    assertEquals(json, ProcessIdentityResolver.extractIdentityJson(statusLines + json));
    assertEquals(json, ProcessIdentityResolver.extractIdentityJson(json + "\n" + statusLines.trim()));
    String prefix = "Value not found for key /decent-registry/identity/" + "ab".repeat(32)
        + "\nFailed to open TCP stream: all attempts to connect to 127.0.0.1:9000 failed\n";
    String suffix = "\nfailed to upgrade security for peer "
        + "12D3KooWBJHhhdqp4zbtGbCX6VyE7hC2ch5uaEvxfwkmSbfo2f3X"
        + ": handshake failed when upgrading to secure connection\n";

    assertEquals(json, ProcessIdentityResolver.extractIdentityJson(prefix + json + suffix));
    assertThrows(IllegalArgumentException.class,
        () -> ProcessIdentityResolver.extractIdentityJson(prefix + json + "\nUnknown trailing output"));
    assertThrows(IllegalArgumentException.class,
        () -> ProcessIdentityResolver.extractIdentityJson("unknown prefix\n" + json));
  }

  @Test
  void rotationAbsenceClassifierRemainsStrictAboutPeerHandshakeFailure() {
    String diagnostics = "failed to upgrade security for peer "
        + "12D3KooWBJHhhdqp4zbtGbCX6VyE7hC2ch5uaEvxfwkmSbfo2f3X"
        + ": handshake failed when upgrading to secure connection\n"
        + "Value not found for key /decent-registry/identity/" + "ab".repeat(32)
        + "\nnot found\n";
    assertFalse(ProcessIdentityResolver.isConfirmedIdentityNotFound(diagnostics));
  }

  @Test
  void recognizedHandshakeDiagnosticsDoNotInvalidateAValidIdentityJsonResult() throws Exception {
    String identity = "mailto:alice@example.org";
    String hex = java.util.HexFormat.of().formatHex(identity.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String key = "11".repeat(32);
    String handshake = "failed to upgrade security for peer "
        + "12D3KooWBJHhhdqp4zbtGbCX6VyE7hC2ch5uaEvxfwkmSbfo2f3X"
        + ": handshake failed when upgrading to secure connection\n";
    String json = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
        java.util.Map.of("identifier", identity, "owner_name_hex", hex,
            "owner_public_key_hex", key, "seq", 2));
    assertEquals(json, ProcessIdentityResolver.extractIdentityJson(handshake + json));
    assertEquals(json, ProcessIdentityResolver.extractIdentityJson(json + "\n" + handshake.trim()));
    Path executable = Files.createTempFile("identity-handshake-stub-", ".sh");
    try {
      String output = handshake + json + "\n";
      String encodedOutput = java.util.Base64.getEncoder().encodeToString(
          output.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(executable, "#!/bin/sh\nprintf '%s' '" + encodedOutput + "' | base64 -d\n");
      executable.toFile().setExecutable(true);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());

      var resolved = resolver.resolveExact(identity);

      assertEquals(identity, resolved.identityId());
      assertArrayEquals(java.util.HexFormat.of().parseHex(key), resolved.publicKey());
    } finally {
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void resolvesExactUtf8IdentityAndValidEd25519Key() throws Exception {
    Path executable = Files.createTempFile("identity-stub-", ".sh");
    try {
      String identifier = "mailto:alice@example.org";
      String hex = java.util.HexFormat.of().formatHex(identifier.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      String key = "11".repeat(32);
      String json = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
          java.util.Map.of("identifier", identifier, "owner_name_hex", hex,
              "owner_public_key_hex", key, "seq", 2));
      String noisy = "Dialing /ip4/127.0.0.1/tcp/9000\nConnected to /ip4/127.0.0.1/tcp/9000/p2p/peer\n"
          + "{\n  \"identifier\": \"" + identifier + "\",\n  \"owner_name_hex\": \"" + hex
          + "\",\n  \"authorization\": {\n    \"operation\": 5,\n    \"state_hash\": \"" + "ab".repeat(32)
          + "\"\n  },\n  \"owner_public_key_hex\": \"" + key + "\",\n  \"seq\": 2\n}\n";
      Files.writeString(executable, "#!/bin/sh\nprintf '%s' '" + noisy + "'\nprintf '\\n'\n");
      executable.toFile().setExecutable(true);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());
      var result = resolver.resolveExact(identifier);
      assertEquals(identifier, result.identityId());
      assertArrayEquals(java.util.HexFormat.of().parseHex(key), result.publicKey());
    } finally {
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void forcedTerminationNeverUsesAnUnboundedWait() throws Exception {
    var process = org.mockito.Mockito.mock(Process.class);
    org.mockito.Mockito.when(process.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)).thenReturn(false);

    assertFalse(ProcessIdentityResolver.terminateProcessWithinGrace(process));

    org.mockito.Mockito.verify(process).destroyForcibly();
    org.mockito.Mockito.verify(process).waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
    org.mockito.Mockito.verify(process, org.mockito.Mockito.never()).waitFor();
  }

  @Test
  void forcedTerminationFailureReportsProcessMayStillRunWithoutUnboundedWait() throws Exception {
    var process = org.mockito.Mockito.mock(Process.class);
    org.mockito.Mockito.doThrow(new UnsupportedOperationException("kill denied"))
        .when(process).destroyForcibly();

    assertFalse(ProcessIdentityResolver.terminateProcessWithinGrace(process));
    org.mockito.Mockito.verify(process, org.mockito.Mockito.never()).waitFor();
  }
}
