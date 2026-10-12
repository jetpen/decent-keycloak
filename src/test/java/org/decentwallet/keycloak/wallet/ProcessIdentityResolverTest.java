package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

final class ProcessIdentityResolverTest {
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

  @Test
  void resolvesOnlyTheRequestedExactUtf8IdentifierAndReturnsRawEd25519Key() throws Exception {
    Path executable = Files.createTempFile("identity-stub-", ".sh");
    try {
      String identifier = "mailto:alice@example.org";
      String hex = java.util.HexFormat.of().formatHex(identifier.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      String key = "11".repeat(32);
      Files.writeString(executable, "#!/bin/sh\nprintf '%s' '{\"identifier\":\"" + identifier
          + "\",\"owner_name_hex\":\"" + hex + "\",\"owner_public_key_hex\":\"" + key + "\",\"seq\":2}'\n");
      executable.toFile().setExecutable(true);

      var resolver = new ProcessIdentityResolver(new String[] {"/ip4/127.0.0.1/tcp/1/p2p/QmTest"},
          8000, executable.toString());
      var resolved = resolver.resolveExact(identifier);

      assertNotNull(resolved);
      assertEquals(identifier, resolved.identityId());
      assertArrayEquals(java.util.HexFormat.of().parseHex(key), resolved.publicKey());
      byte[] spkiPrefix = {0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00};
      byte[] spki = java.util.Arrays.copyOf(spkiPrefix, spkiPrefix.length + resolved.publicKey().length);
      System.arraycopy(resolved.publicKey(), 0, spki, spkiPrefix.length, resolved.publicKey().length);
      assertNotNull(java.security.KeyFactory.getInstance("Ed25519").generatePublic(
          new java.security.spec.X509EncodedKeySpec(spki)));
    } finally {
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void acceptsKnownRegistryDialWarningsBeforeOneValidJsonResult() throws Exception {
    Path executable = Files.createTempFile("identity-stub-", ".sh");
    try {
      String identifier = "mailto:alice@example.org";
      String hex = java.util.HexFormat.of().formatHex(identifier.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      String key = "11".repeat(32);
      String json = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
          java.util.Map.of("identifier", identifier, "owner_name_hex", hex,
              "owner_public_key_hex", key, "seq", 2));
      String script = String.join(System.lineSeparator(), "#!/bin/sh",
          "echo 'Failed to open TCP stream: all attempts to connect to 127.0.0.1:9000 failed'",
          "printf '%s' '" + json + "'", "");
      Files.writeString(executable, script);
      executable.toFile().setExecutable(true);

      var resolver = new ProcessIdentityResolver(new String[] {"/ip4/127.0.0.1/tcp/1/p2p/QmTest"},
          8000, executable.toString());
      var resolved = resolver.resolveExact(identifier);

      assertNotNull(resolved);
      assertEquals(identifier, resolved.identityId());
      assertArrayEquals(java.util.HexFormat.of().parseHex(key), resolved.publicKey());
    } finally {
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void rejectsTrailingContentAfterIdentityJson() throws Exception {
    Path executable = Files.createTempFile("identity-stub-", ".sh");
    try {
      String identifier = "mailto:alice@example.org";
      String hex = java.util.HexFormat.of().formatHex(identifier.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      String json = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
          java.util.Map.of("identifier", identifier, "owner_name_hex", hex,
              "owner_public_key_hex", "11".repeat(32), "seq", 2));
      Files.writeString(executable, String.join(System.lineSeparator(), "#!/bin/sh",
          "printf '%s' '" + json + " trailing-data'", ""));
      executable.toFile().setExecutable(true);

      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());

      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact(identifier));
    } finally {
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void rejectsUnpairedSurrogateBeforeStartingIdentityProcess() {
    var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, "/bin/true");

    var failure = assertThrows(IllegalArgumentException.class,
        () -> resolver.resolveExact("wallet-\uD800"));
    assertEquals("Identity ID must be valid Unicode", failure.getMessage());
  }

  @Test
  void rejectsARegistryResultForAnotherExactIdentifier() throws Exception {
    Path executable = Files.createTempFile("identity-stub-", ".sh");
    try {
      String requested = "mailto:alice@example.org";
      String different = "mailto:Alice@example.org";
      String hex = java.util.HexFormat.of().formatHex(different.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(executable, "#!/bin/sh\nprintf '%s' '{\"identifier\":\"" + different
          + "\",\"owner_name_hex\":\"" + hex + "\",\"owner_public_key_hex\":\"" + "11".repeat(32) + "\"}'\n");
      executable.toFile().setExecutable(true);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());
      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact(requested));
    } finally {
      Files.deleteIfExists(executable);
    }
  }
}
