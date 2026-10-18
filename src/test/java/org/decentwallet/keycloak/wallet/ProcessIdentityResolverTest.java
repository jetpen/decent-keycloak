package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

final class ProcessIdentityResolverTest {
  @Test
  void diagnosticLoggerEmitsOnlyBoundedCategoriesAndLineCount() throws Exception {
    String privateMarker = "private@example.invalid";
    String endpointMarker = "/ip4/10.20.30.40/tcp/9000";
    String raw = "Failed to open TCP stream: all attempts to connect to " + endpointMarker + " failed\n"
        + "Value not found for key /decent-registry/identity/" + "ab".repeat(32) + "\n"
        + "unclassified " + privateMarker + " token=must-not-log";
    Path executable = Files.createTempFile("identity-diagnostic-stub-", ".sh");
    var capture = new ResolverLogCapture();
    var old = java.util.logging.Logger.getLogger(ProcessIdentityResolver.class.getName());
    var oldLevel = old.getLevel();
    try {
      String encoded = java.util.Base64.getEncoder().encodeToString(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(executable, "#!/bin/sh\nprintf '%s' '" + encoded + "' | base64 -d\n");
      executable.toFile().setExecutable(true);
      old.addHandler(capture);
      old.setLevel(java.util.logging.Level.FINE);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());

      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact("mailto:alice@example.org"));

      assertTrue(capture.message.startsWith("[WALLET-RESOLVER-DIAG] "), capture.message);
      assertTrue(capture.message.contains("reason=registry_miss|dial_warning|unknown"), capture.message);
      assertTrue(capture.message.contains("lines=3"), capture.message);
      assertFalse(capture.message.contains(privateMarker));
      assertFalse(capture.message.contains(endpointMarker));
      assertFalse(capture.message.contains("must-not-log"));
      assertFalse(capture.message.contains(raw));
      assertTrue(java.util.regex.Pattern.matches(
          "\\[WALLET-RESOLVER-DIAG] exit=0, reason=[a-z_|]+, lines=3, capped=false",
          capture.message));
    } finally {
      old.removeHandler(capture);
      old.setLevel(oldLevel);
      Files.deleteIfExists(executable);
    }
  }

  private static final class ResolverLogCapture extends java.util.logging.Handler {
    private String message = "";
    @Override public void publish(java.util.logging.LogRecord record) { message = record.getMessage(); }
    @Override public void flush() {}
    @Override public void close() {}
  }

  @Test
  void processStartFailureIsWrappedAndLoggedAsSanitizedCategory() throws Exception {
    Path directory = Files.createTempDirectory("identity-start-failure-");
    Path missingExecutable = directory.resolve("missing-identity");
    var underlying = java.util.logging.LogManager.getLogManager().getLogger(
        ProcessIdentityResolver.class.getName());
    var capture = new ResolverLogCapture();
    var oldLevel = underlying.getLevel();
    try {
      underlying.addHandler(capture);
      underlying.setLevel(java.util.logging.Level.FINE);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, missingExecutable.toString());

      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact("mailto:alice@example.org"));

      assertTrue(capture.message.contains("reason=process_start"), capture.message);
      assertTrue(capture.message.contains("exit=-1"), capture.message);
      assertFalse(capture.message.contains(missingExecutable.toString()));
    } finally {
      underlying.removeHandler(capture);
      underlying.setLevel(oldLevel);
      Files.deleteIfExists(missingExecutable);
      Files.deleteIfExists(directory);
    }
  }

  @Test
  void outputOverflowEmitsFixedCategoryWithoutOutputContent() throws Exception {
    String marker = "private-overflow-marker@example.invalid";
    String raw = marker + "x".repeat(20000);
    Path executable = Files.createTempFile("identity-overflow-diagnostic-", ".sh");
    var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());
    var logger = java.util.logging.LogManager.getLogManager().getLogger(
        ProcessIdentityResolver.class.getName());
    var capture = new ResolverLogCapture();
    var oldLevel = logger.getLevel();
    try {
      String encoded = java.util.Base64.getEncoder().encodeToString(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(executable, String.join(System.lineSeparator(),
          "#!/bin/sh", "printf '%s' '" + encoded + "' | base64 -d", ""));
      executable.toFile().setExecutable(true);
      logger.addHandler(capture);
      logger.setLevel(java.util.logging.Level.FINE);

      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact("mailto:alice@example.org"));

      assertTrue(capture.message.contains("output_overflow"), capture.message);
      assertFalse(capture.message.contains(marker));
      assertFalse(capture.message.contains(raw));
    } finally {
      logger.removeHandler(capture);
      logger.setLevel(oldLevel);
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void timeoutEmitsFixedCategoryWithoutResolverOutput() throws Exception {
    String marker = "private-timeout-marker@example.invalid";
    Path executable = Files.createTempFile("identity-timeout-diagnostic-", ".sh");
    var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());
    var logger = java.util.logging.LogManager.getLogManager().getLogger(
        ProcessIdentityResolver.class.getName());
    var capture = new ResolverLogCapture();
    var oldLevel = logger.getLevel();
    try {
      String encoded = java.util.Base64.getEncoder().encodeToString(marker.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(executable, String.join(System.lineSeparator(),
          "#!/bin/sh", "printf '%s' '" + encoded + "'", "sleep 30", ""));
      executable.toFile().setExecutable(true);
      logger.addHandler(capture);
      logger.setLevel(java.util.logging.Level.FINE);

      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact("mailto:alice@example.org"));

      assertTrue(capture.message.contains("timeout"), capture.message);
      assertFalse(capture.message.contains(marker));
    } finally {
      logger.removeHandler(capture);
      logger.setLevel(oldLevel);
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void interruptionEmitsFixedCategoryAndRestoresInterruptStatus() throws Exception {
    String marker = "private-interrupted-marker@example.invalid";
    Path executable = Files.createTempFile("identity-interrupted-diagnostic-", ".sh");
    Path started = executable.resolveSibling(executable.getFileName() + ".started");
    var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());
    var logger = java.util.logging.LogManager.getLogManager().getLogger(
        ProcessIdentityResolver.class.getName());
    var capture = new ResolverLogCapture();
    var oldLevel = logger.getLevel();
    var failure = new java.util.concurrent.atomic.AtomicReference<Throwable>();
    var interruptRestored = new java.util.concurrent.atomic.AtomicBoolean();
    Thread lookup = null;
    try {
      String encoded = java.util.Base64.getEncoder().encodeToString(marker.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(executable, String.join(System.lineSeparator(),
          "#!/bin/sh", "printf '%s' '" + encoded + "'", "touch '" + started + "'", "sleep 30", ""));
      executable.toFile().setExecutable(true);
      logger.addHandler(capture);
      logger.setLevel(java.util.logging.Level.FINE);
      lookup = Thread.ofPlatform().start(() -> {
        try {
          resolver.resolveExact("mailto:alice@example.org");
        } catch (Throwable thrown) {
          failure.set(thrown);
          interruptRestored.set(Thread.currentThread().isInterrupted());
        }
      });
      long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
      while (!Files.exists(started) && System.nanoTime() < deadline) Thread.sleep(10);
      assertTrue(Files.exists(started), "resolver subprocess did not reach its wait state");

      lookup.interrupt();
      lookup.join(5000);

      assertFalse(lookup.isAlive(), "interrupted resolver thread did not finish");
      assertInstanceOf(ProcessIdentityResolver.IdentityResolutionException.class, failure.get());
      assertTrue(interruptRestored.get());
      assertTrue(capture.message.contains("interrupted"), capture.message);
      assertFalse(capture.message.contains(marker));
    } finally {
      if (lookup != null && lookup.isAlive()) {
        lookup.interrupt();
        lookup.join(5000);
      }
      logger.removeHandler(capture);
      logger.setLevel(oldLevel);
      Files.deleteIfExists(started);
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void historyUnavailablePathEmitsSanitizedDiagnosticCategories() throws Exception {
    String raw = "";
    Path executable = Files.createTempFile("identity-history-diagnostic-", ".sh");
    var underlying = java.util.logging.LogManager.getLogManager().getLogger(
        ProcessIdentityResolver.class.getName());
    var capture = new ResolverLogCapture();
    var oldLevel = underlying.getLevel();
    try {
      String encoded = java.util.Base64.getEncoder().encodeToString(
          raw.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(executable, "#!/bin/sh\nprintf '%s' '" + encoded + "' | base64 -d\nexit 3\n");
      executable.toFile().setExecutable(true);
      underlying.addHandler(capture);
      underlying.setLevel(java.util.logging.Level.FINE);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());

      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact("mailto:alice@example.org"));

      assertTrue(capture.message.startsWith("[WALLET-RESOLVER-DIAG] "), capture.message);
      assertTrue(capture.message.contains("reason=history_unavailable"), capture.message);
      assertFalse(capture.message.contains("private@example.invalid"));
      assertFalse(capture.message.contains("must-not-log"));
    } finally {
      underlying.removeHandler(capture);
      underlying.setLevel(oldLevel);
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void diagnosticsAreReducedToBoundedAllowlistedCategories() {
    String output = String.join("\n",
        "Failed to open TCP stream: all attempts to connect to /ip4/10.1.2.3/tcp/9000 failed",
        "Value not found for key /decent-registry/identity/" + "ab".repeat(32),
        "failed to upgrade security for peer 12D3KooWBJHhhdqp4zbtGbCX6VyE7hC2ch5uaEvxfwkmSbfo2f3X: handshake failed",
        "history unavailable: peer-specific private details",
        "Traceback (most recent call last): private@example.invalid",
        "unclassified output private@example.invalid token=never-log");

    String categories = ProcessIdentityResolver.diagnosticReason(output);

    assertEquals("registry_miss,dial_warning,peer_handshake,history_unavailable,traceback,unknown", categories);
    assertFalse(categories.contains("private"));
    assertFalse(categories.contains("10.1.2.3"));
    assertFalse(categories.contains("token"));
  }

  @Test
  void identityStartingWithDashIsPassedAsAnOptionValue() throws Exception {
    String identity = "-mailto:alice@example.org";
    String encodedIdentity = java.util.HexFormat.of().formatHex(
        identity.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    String key = "11".repeat(32);
    String json = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
        java.util.Map.of("identifier", identity, "owner_name_hex", encodedIdentity,
            "owner_public_key_hex", key, "seq", 2));
    String encodedJson = java.util.Base64.getEncoder().encodeToString(
        json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    Path executable = Files.createTempFile("identity-leading-dash-", ".sh");
    try {
      Files.writeString(executable, String.join(System.lineSeparator(),
          "#!/bin/sh",
          "if [ \"$1\" != \"get\" ] || [ \"$2\" != '--identifier=-mailto:alice@example.org' ]; then exit 7; fi",
          "printf '%s' '" + encodedJson + "' | base64 -d",
          ""));
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
  void validIdentityJsonLinesAreNotReportedAsUnknownDiagnostics() {
    String json = "{\n  \"identifier\": \"mailto:alice@example.org\",\n  \"seq\": 2\n}";

    assertEquals("", ProcessIdentityResolver.diagnosticReason(json));
  }

  @Test
  void unknownDiagnosticCategoriesAndLineCountsAreCapped() {
    String output = String.join("\n", java.util.Collections.nCopies(100, "unclassified").toArray(String[]::new));

    assertEquals("unknown", ProcessIdentityResolver.diagnosticReason(output));
    assertEquals(100, ProcessIdentityResolver.nonEmptyLineCount(output));
  }

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
    assertFalse(ProcessIdentityResolver.isConfirmedIdentityNotFound(diagnostics,
        ProcessIdentityResolver.exactRegistryObjectKeyHex("mailto:alice@example.org")));
  }

  @Test
  void handshakeDiagnosticsMakePositiveIdentityLookupUnavailable() throws Exception {
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

      var failure = assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact(identity));
      assertEquals("Identity lookup diagnostics were inconclusive", failure.getMessage());
    } finally {
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void identityMissMustNameTheRequestedRegistryObjectKey() {
    String identity = "mailto:alice@example.org";
    String expectedObjectKey = "4aa8889aa1e3f193844b32d36e58b50a8817304b9e15d798d460d00bff828a29";
    String exactMiss = "Value not found for key /decent-registry/identity/" + expectedObjectKey
        + "\nnot found\n";

    assertEquals(expectedObjectKey, ProcessIdentityResolver.exactRegistryObjectKeyHex(identity));
    assertTrue(ProcessIdentityResolver.isConfirmedIdentityNotFound(exactMiss, expectedObjectKey));
    assertFalse(ProcessIdentityResolver.isConfirmedIdentityNotFound(exactMiss, "ab".repeat(32)));
  }

  @Test
  void identityMissForDifferentRegistryObjectDoesNotEstablishAbsence() throws Exception {
    String identity = "mailto:alice@example.org";
    String wrongKeyDiagnostics = "Value not found for key /decent-registry/identity/" + "ab".repeat(32)
        + "\nnot found\n";
    String expectedObjectKey = ProcessIdentityResolver.exactRegistryObjectKeyHex(identity);
    String mixedKeyDiagnostics = "Value not found for key /decent-registry/identity/" + expectedObjectKey
        + "\nValue not found for key /decent-registry/identity/" + "ab".repeat(32) + "\nnot found\n";
    assertFalse(ProcessIdentityResolver.isConfirmedIdentityNotFound(wrongKeyDiagnostics, expectedObjectKey));
    assertFalse(ProcessIdentityResolver.isConfirmedIdentityNotFound(mixedKeyDiagnostics, expectedObjectKey));

    Path executable = Files.createTempFile("identity-wrong-miss-stub-", ".sh");
    try {
      String encodedOutput = java.util.Base64.getEncoder().encodeToString(
          wrongKeyDiagnostics.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(executable, "#!/bin/sh\nprintf '%s' '" + encodedOutput
          + "' | base64 -d\nexit 1\n");
      executable.toFile().setExecutable(true);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString());

      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact("mailto:alice@example.org"));
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
