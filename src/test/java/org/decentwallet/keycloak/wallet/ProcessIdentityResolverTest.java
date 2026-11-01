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
    String raw = String.join(System.lineSeparator(),
        "Failed to open TCP stream: all attempts to connect to " + endpointMarker + " failed",
        "Value not found for key /decent-registry/identity/" + "ab".repeat(32),
        "DHT_LOOKUP_SUMMARY stage=get_value attempts=2 empty=1 failed=1 timeouts=0 incomplete=0",
        "unclassified " + privateMarker + " token=must-not-log");
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
      assertTrue(capture.message.contains("reason=registry_miss|dial_warning|dht_lookup_unavailable|unknown"), capture.message);
      assertTrue(capture.message.contains("lines=4"), capture.message);
      assertFalse(capture.message.contains(privateMarker));
      assertFalse(capture.message.contains(endpointMarker));
      assertFalse(capture.message.contains("must-not-log"));
      assertFalse(capture.message.contains(raw));
      assertTrue(java.util.regex.Pattern.matches(
          "\\[WALLET-RESOLVER-DIAG] exit=0, reason=[a-z_|]+, lines=4, capped=false, dht=get_value:2/1/1/0/0",
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
    String cleanSummaries = "DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=1 failed=0 timeouts=0 incomplete=0\n"
        + "DHT_LOOKUP_SUMMARY stage=remote_identity attempts=2 empty=2 failed=0 timeouts=0 incomplete=0\n";
    String exactMiss = cleanSummaries + "Value not found for key /decent-registry/identity/" + expectedObjectKey
        + "\nnot found\n";

    assertEquals(expectedObjectKey, ProcessIdentityResolver.exactRegistryObjectKeyHex(identity));
    assertTrue(ProcessIdentityResolver.isConfirmedIdentityNotFound(exactMiss, expectedObjectKey));
    assertFalse(ProcessIdentityResolver.isConfirmedIdentityNotFound(
        "Value not found for key /decent-registry/identity/" + expectedObjectKey + "\nnot found\n",
        expectedObjectKey));
    assertFalse(ProcessIdentityResolver.isConfirmedIdentityNotFound(exactMiss, "ab".repeat(32)));
    String mixedOutcome = "DHT_LOOKUP_SUMMARY stage=get_value attempts=2 empty=1 failed=1 timeouts=0 incomplete=0\n"
        + cleanSummaries.substring(cleanSummaries.indexOf("DHT_LOOKUP_SUMMARY stage=remote_identity"))
        + "Value not found for key /decent-registry/identity/" + expectedObjectKey + "\nnot found\n";
    assertFalse(ProcessIdentityResolver.isConfirmedIdentityNotFound(mixedOutcome, expectedObjectKey));
    assertEquals("dht_lookup_unavailable", ProcessIdentityResolver.diagnosticReason(
        "DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=0 failed=1 timeouts=0 incomplete=0"));
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
    String dialWarningDiagnostics = "Failed to open TCP stream: all attempts to connect to 127.0.0.1:9000 failed\n"
        + "Value not found for key /decent-registry/identity/" + expectedObjectKey + "\nnot found\n";
    assertFalse(ProcessIdentityResolver.isConfirmedIdentityNotFound(dialWarningDiagnostics, expectedObjectKey));

    Path warningExecutable = Files.createTempFile("identity-dial-warning-miss-stub-", ".sh");
    try {
      String encodedOutput = java.util.Base64.getEncoder().encodeToString(
          dialWarningDiagnostics.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(warningExecutable, "#!/bin/sh\nprintf '%s' '" + encodedOutput
          + "' | base64 -d\nexit 1\n");
      warningExecutable.toFile().setExecutable(true);
      var resolver = new ProcessIdentityResolver(new String[] {"peer"}, 8000, warningExecutable.toString());

      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolver.resolveExact(identity));
    } finally {
      Files.deleteIfExists(warningExecutable);
    }

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
  void recoveredRotationSummaryAllowsExactCurrentOwnerResolution() throws Exception {
    String identifier = "rotation-summary@example.invalid";
    String key = "11".repeat(32);
    String json = rotationResultJson(identifier, key);
    String summary = "DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=0 failed=0 timeouts=0 incomplete=0";
    for (String output : java.util.List.of(summary + "\n" + json, json + "\n" + summary)) {
      var resolved = resolveScriptedOutput(identifier, output, 0);
      assertEquals(identifier, resolved.identityId());
      assertArrayEquals(java.util.HexFormat.of().parseHex(key), resolved.publicKey());
    }
  }

  @Test
  void positiveRotationOutputCannotHideUncertainOrDuplicateSummaries() throws Exception {
    String identifier = "rotation-summary@example.invalid";
    String json = rotationResultJson(identifier, "11".repeat(32));
    String summary = "DHT_LOOKUP_SUMMARY stage=get_value attempts=1 empty=0 failed=0 timeouts=0 incomplete=0";
    for (String prefix : java.util.List.of(
        summary.replace("attempts=1", "attempts=0"),
        summary.replace("empty=0", "empty=999"),
        summary.replace("failed=0", "failed=1"),
        summary.replace("timeouts=0", "timeouts=1"),
        summary.replace("incomplete=0", "incomplete=1"),
        summary.replace("attempts=1", "attempts=1000"),
        summary + "\n" + summary,
        summary + "\nunknown private-marker=never-log")) {
      assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
          () -> resolveScriptedOutput(identifier, prefix + "\n" + json, 0));
    }
    assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
        () -> resolveScriptedOutput(identifier, summary + "\n" + json, 1));
    assertThrows(ProcessIdentityResolver.IdentityResolutionException.class,
        () -> resolveScriptedOutput("other@example.invalid", summary + "\n" + json, 0));
  }

  private static String rotationResultJson(String identifier, String key) throws Exception {
    String hex = java.util.HexFormat.of().formatHex(identifier.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    return new com.fasterxml.jackson.databind.ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(
        java.util.Map.of("identifier", identifier, "owner_name_hex", hex,
            "owner_public_key_hex", key, "seq", 2,
            "authorization", java.util.Map.of("operation", 5, "threshold", 2,
                "signer_set", java.util.List.of(
                    java.util.Map.of("signer_id", "new", "public_key", key),
                    java.util.Map.of("signer_id", "old", "public_key", "22".repeat(32)),
                    java.util.Map.of("signer_id", "cosigner", "public_key", "33".repeat(32))))));
  }

  private static WalletIdentityKeyResolver.ResolvedIdentityKey resolveScriptedOutput(
      String identity, String output, int exitCode) throws Exception {
    Path executable = Files.createTempFile("identity-rotation-summary-", ".sh");
    try {
      String encodedOutput = java.util.Base64.getEncoder().encodeToString(
          output.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      Files.writeString(executable, "#!/bin/sh\nprintf '%s' '" + encodedOutput
          + "' | base64 -d\nexit " + exitCode + "\n");
      executable.toFile().setExecutable(true);
      return new ProcessIdentityResolver(new String[] {"peer"}, 8000, executable.toString()).resolveExact(identity);
    } finally {
      Files.deleteIfExists(executable);
    }
  }

  @Test
  void concurrentResolverInstancesAvoidConfiguredListenerPortCollision() throws Exception {
    String firstIdentity = "mailto:first-account@example.org";
    String secondIdentity = "mailto:second-account@example.org";
    Path directory = Files.createTempDirectory("identity-concurrent-listener-");
    Path executable = directory.resolve("identity-fixture");
    int configuredPort;
    try (var reservation = new java.net.ServerSocket(0)) {
      configuredPort = reservation.getLocalPort();
    }
    String root = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(directory.toString());
    String script = """
        #!/usr/bin/python3
        import json, os, pathlib, socket, sys, time
        root = pathlib.Path(ROOT)
        args = sys.argv[1:]
        identity = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--identifier="))
        port = int(args[args.index("--port") + 1])
        (root / ("requested-" + str(os.getpid()))).write_text(str(port))
        (root / ("started-" + str(os.getpid()))).touch()
        deadline = time.monotonic() + 5
        while len(list(root.glob("started-*"))) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        listener = socket.socket()
        try:
            listener.bind(("127.0.0.1", port))
            listener.listen()
        except OSError:
            print("Failed to start TCP listener", file=sys.stderr)
            sys.exit(1)
        (root / ("bound-" + str(os.getpid()))).write_text(str(listener.getsockname()[1]))
        print(json.dumps({"identifier": identity, "owner_name_hex": identity.encode().hex(),
            "owner_public_key_hex": "11" * 32, "seq": 0}))
        time.sleep(0.3)
        listener.close()
        """.replace("ROOT", root);
    Files.writeString(executable, script);
    executable.toFile().setExecutable(true);
    var firstResolver = new ProcessIdentityResolver(new String[] {"peer"}, configuredPort, executable.toString());
    var secondResolver = new ProcessIdentityResolver(new String[] {"peer"}, configuredPort, executable.toString());
    var executor = java.util.concurrent.Executors.newFixedThreadPool(2);
    try {
      var first = executor.submit(() -> firstResolver.resolveExact(firstIdentity));
      var second = executor.submit(() -> secondResolver.resolveExact(secondIdentity));
      var results = new java.util.ArrayList<WalletIdentityKeyResolver.ResolvedIdentityKey>();
      var lookupFailures = new java.util.ArrayList<String>();
      for (var future : java.util.List.of(first, second)) {
        try { results.add(future.get(8, java.util.concurrent.TimeUnit.SECONDS)); }
        catch (java.util.concurrent.ExecutionException failedLookup) {
          Throwable cause = failedLookup.getCause();
          lookupFailures.add(cause == null ? "unknown" : cause.getClass().getSimpleName());
        }
      }
      assertEquals(2, results.size(),
          "both concurrent resolver subprocesses must complete; failures=" + lookupFailures);
      assertEquals(java.util.Set.of(firstIdentity, secondIdentity), results.stream()
          .map(WalletIdentityKeyResolver.ResolvedIdentityKey::identityId)
          .collect(java.util.stream.Collectors.toSet()));
      try (var files = Files.list(directory)) {
        var requestedPorts = files.filter(path -> path.getFileName().toString().startsWith("requested-"))
            .map(path -> {
              try { return Files.readString(path); }
              catch (java.io.IOException failure) { throw new java.io.UncheckedIOException(failure); }
            }).collect(java.util.stream.Collectors.toSet());
        assertEquals(java.util.Set.of(Integer.toString(configuredPort), "0"), requestedPorts);
      }
      try (var files = Files.list(directory)) {
        var boundPorts = files.filter(path -> path.getFileName().toString().startsWith("bound-"))
            .map(path -> {
              try { return Files.readString(path); }
              catch (java.io.IOException failure) { throw new java.io.UncheckedIOException(failure); }
            }).toList();
        assertEquals(2, boundPorts.size());
        assertEquals(2, new java.util.HashSet<>(boundPorts).size());
      }
    } finally {
      executor.shutdownNow();
      executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS);
      try (var paths = Files.walk(directory)) {
        paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
          try { Files.deleteIfExists(path); }
          catch (java.io.IOException failure) { throw new java.io.UncheckedIOException(failure); }
        });
      }
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
