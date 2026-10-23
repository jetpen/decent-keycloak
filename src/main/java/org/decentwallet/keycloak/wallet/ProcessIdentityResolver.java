package org.decentwallet.keycloak.wallet;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Calls the decent-identity CLI and requires its result to preserve the exact identifier bytes. */
public final class ProcessIdentityResolver implements WalletIdentityKeyResolver {
  private static final long TIMEOUT_SECONDS = 10;
  private static final long FORCED_TERMINATION_WAIT_SECONDS = 2;
  private static final int MAX_OUTPUT_BYTES = 16384;
  private static final String DIAL_WARNING_PREFIX =
      "Failed to open TCP stream: all attempts to connect to ";
  private static final String DIAL_WARNING_SUFFIX = " failed";
  private static final String REGISTRY_MISS_PREFIX = "Value not found for key /decent-registry/identity/";
  private static final String CONNECTED_PREFIX = "Connected to ";
  private static final String DIALING_PREFIX = "Dialing ";
  private static final int IDENTITY_OBJECT_KEY_HEX_LENGTH = 64;
  private static final int MAX_DIAGNOSTIC_LINES = 64;
  private static final Pattern DHT_LOOKUP_SUMMARY_PATTERN = Pattern.compile(
      "DHT_LOOKUP_SUMMARY stage=(get_value|remote_identity) attempts=(\\d{1,3}) empty=(\\d{1,3}) "
          + "failed=(\\d{1,3}) timeouts=(\\d{1,3}) incomplete=(\\d{1,3})");
  private static final org.jboss.logging.Logger LOG =
      org.jboss.logging.Logger.getLogger(ProcessIdentityResolver.class);
  private static final ObjectMapper RESULT_MAPPER = new ObjectMapper(
      JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
      .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private final List<String> bootstrap;
  private final int clientPort;
  private final String executable;

  public ProcessIdentityResolver(String[] bootstrap, int clientPort) {
    this(bootstrap, clientPort, System.getProperty("decent.identity.executable", "decent-identity"));
  }

  ProcessIdentityResolver(String[] bootstrap, int clientPort, String executable) {
    if (bootstrap == null || bootstrap.length == 0) throw new IllegalArgumentException("Registry bootstrap is required");
    if (clientPort < 1 || clientPort > 65535) throw new IllegalArgumentException("Identity client port rejected");
    this.bootstrap = List.of(bootstrap.clone());
    this.clientPort = clientPort;
    this.executable = java.util.Objects.requireNonNull(executable);
  }

  @Override
  public WalletIdentityKeyResolver.ResolvedIdentityKey resolveExact(String identityId) throws Exception {
    if (identityId == null || identityId.isEmpty() || identityId.length() > 1024
        || identityId.indexOf('\0') >= 0) throw new IllegalArgumentException("Identity ID rejected");
    try {
      java.nio.charset.StandardCharsets.UTF_8.newEncoder()
          .encode(java.nio.CharBuffer.wrap(identityId));
    } catch (java.nio.charset.CharacterCodingException invalidUnicode) {
      throw new IllegalArgumentException("Identity ID must be valid Unicode", invalidUnicode);
    }
    String exactHex = HexFormat.of().formatHex(identityId.getBytes(StandardCharsets.UTF_8));
    var command = new java.util.ArrayList<String>();
    command.add(executable);
    command.add("get");
    command.add("--identifier=" + identityId);
    command.add("--host");
    command.add("127.0.0.1");
    command.add("--port");
    command.add(Integer.toString(clientPort));
    for (String peer : bootstrap) { command.add("--bootstrap"); command.add(peer); }

    ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
    builder.environment().clear();
    builder.environment().put("PATH", "/usr/local/bin:/usr/bin:/bin");
    builder.environment().put("LANG", "C.UTF-8");
    Process process;
    try {
      process = builder.start();
    } catch (java.io.IOException startFailure) {
      logSanitizedDiagnostics("", -1, "process_start");
      throw new IdentityResolutionException("Identity process could not start", startFailure);
    }
    BoundedOutput output = new BoundedOutput(MAX_OUTPUT_BYTES);
    Thread reader = Thread.ofPlatform().daemon().start(() -> output.drain(process.getInputStream()));
    final boolean finished;
    try {
      finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    } catch (InterruptedException interrupted) {
      boolean terminated = false;
      try { terminated = terminateProcessWithinGrace(process); }
      catch (InterruptedException terminationInterrupted) { interrupted.addSuppressed(terminationInterrupted); }
      logSanitizedDiagnostics(output.text(), -1, "interrupted");
      Thread.currentThread().interrupt();
      throw new IdentityResolutionException("Identity lookup interrupted", !terminated);
    }
    if (!finished) {
      boolean terminated;
      try { terminated = terminateProcessWithinGrace(process); }
      catch (InterruptedException interrupted) {
        logSanitizedDiagnostics(output.text(), -1, "termination_interrupted");
        Thread.currentThread().interrupt();
        throw new IdentityResolutionException("Identity lookup termination interrupted", true);
      }
      logSanitizedDiagnostics(output.text(), -1, "timeout");
      throw new IdentityResolutionException("Identity lookup timed out", !terminated);
    }
    reader.join(TimeUnit.SECONDS.toMillis(1));
    int exit = process.exitValue();
    String outputText = output.text();
    if (output.overflowed()) {
      logSanitizedDiagnostics(outputText, exit, "output_overflow");
      throw new IdentityResolutionException("Identity lookup response exceeded limit");
    }
    if (exit == 1 && isConfirmedIdentityNotFound(outputText, exactRegistryObjectKeyHex(identityId))) {
      logSanitizedDiagnostics(outputText, exit, "not_found");
      return null;
    }
    if (exit == 3 || stripRecognizedDhtDiagnostics(outputText).startsWith("history unavailable:")) {
      logSanitizedDiagnostics(outputText, exit, "history_unavailable");
      throw new IdentityResolutionException("Identity history unavailable");
    }
    if (exit != 0) {
      logSanitizedDiagnostics(outputText, exit, "nonzero_exit");
      throw new IdentityResolutionException("Identity lookup failed");
    }
    String diagnostics = diagnosticReason(outputText);
    if (!diagnostics.isEmpty() && !"dial_warning".equals(diagnostics)) {
      logSanitizedDiagnostics(outputText, exit, diagnostics);
      throw new IdentityResolutionException("Identity lookup diagnostics were inconclusive");
    }
    try {
      IdentityResolutionResult result = RESULT_MAPPER.readValue(extractIdentityJson(outputText), IdentityResolutionResult.class);
      if (result.seq < 0 || !identityId.equals(result.identifier) || result.ownerNameHex == null
          || result.ownerPublicKeyHex == null || !exactHex.equalsIgnoreCase(result.ownerNameHex)) {
        throw new IdentityResolutionException("Identity result did not match exact identifier");
      }
      byte[] publicKey = HexFormat.of().parseHex(result.ownerPublicKeyHex);
      if (publicKey.length != 32) throw new IdentityResolutionException("Identity public key size rejected");
      byte[] prefix = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
      byte[] spki = new byte[prefix.length + publicKey.length];
      System.arraycopy(prefix, 0, spki, 0, prefix.length);
      System.arraycopy(publicKey, 0, spki, prefix.length, publicKey.length);
      java.security.KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
      return new ResolvedIdentityKey(identityId, publicKey);
    } catch (IdentityResolutionException ex) {
      logSanitizedDiagnostics(outputText, exit, diagnosticReason(outputText));
      throw ex;
    } catch (Exception ex) {
      logSanitizedDiagnostics(outputText, exit, diagnosticReason(outputText));
      throw new IdentityResolutionException("Identity lookup result was invalid", ex);
    }
  }

  static String diagnosticReason(String output) {
    String[] lines = output.split("\\R", -1);
    boolean registryMiss = false;
    boolean dialWarning = false;
    boolean peerHandshake = false;
    boolean peerError = false;
    boolean historyUnavailable = false;
    boolean traceback = false;
    boolean dhtLookupUnavailable = false;
    int unknown = 0;
    for (String line : lines) {
      if (line.isBlank()) continue;
      DhtLookupSummary summary = parseDhtLookupSummary(line);
      if (summary != null) {
        if (!summary.isCleanAbsence()) dhtLookupUnavailable = true;
      }
      else if (line.startsWith("DHT_LOOKUP_SUMMARY ")) unknown = Math.min(unknown + 1, MAX_DIAGNOSTIC_LINES);
      else if (line.startsWith("history unavailable:")) historyUnavailable = true;
      else if (line.startsWith("Traceback") || line.startsWith("File ") || line.contains("Error:")) traceback = true;
      else if (isRegistryIdentityMiss(line)) registryMiss = true;
      else if (isKnownDialWarning(line)) dialWarning = true;
      else if (isPeerHandshakeFailure(line)) peerHandshake = true;
      else if (line.startsWith("Failed to send request to peer: ")
          || line.startsWith("Failed to connect to peer: ")) peerError = true;
      else if (isJsonStructuralLine(line) || isPeerStatusLine(line)) { }
      else unknown = Math.min(unknown + 1, MAX_DIAGNOSTIC_LINES);
    }
    return String.join(",", java.util.stream.Stream.of(
        registryMiss ? "registry_miss" : null,
        dialWarning ? "dial_warning" : null,
        peerHandshake ? "peer_handshake" : null,
        peerError ? "peer_error" : null,
        historyUnavailable ? "history_unavailable" : null,
        dhtLookupUnavailable ? "dht_lookup_unavailable" : null,
        traceback ? "traceback" : null,
        unknown > 0 ? "unknown" : null)
        .filter(java.util.Objects::nonNull).toList());
  }

  private static boolean isJsonStructuralLine(String line) {
    String trimmed = line.stripLeading();
    return trimmed.startsWith("{") || trimmed.startsWith("}") || trimmed.startsWith("[")
        || trimmed.startsWith("]") || trimmed.startsWith("\"");
  }

  private static boolean isPeerStatusLine(String line) {
    if (!line.startsWith(DIALING_PREFIX) && !line.startsWith(CONNECTED_PREFIX)) return false;
    String value = line.substring(line.indexOf(' ') + 1);
    return !value.isBlank();
  }

  static int nonEmptyLineCount(String output) {
    return (int) java.util.Arrays.stream(output.split("\\R", -1)).filter(line -> !line.isBlank()).count();
  }

  private static void logSanitizedDiagnostics(String output, int exit, String fallback) {
    int totalLines = nonEmptyLineCount(output);
    String reason = diagnosticReason(output);
    if (reason.isEmpty()) reason = fallback;
    else if (java.util.Set.of("timeout", "interrupted", "termination_interrupted", "output_overflow")
        .contains(fallback) && !java.util.List.of(reason.split(",")).contains(fallback)) {
      reason += "," + fallback;
    }
    if (reason == null || !reason.matches("[a-z_,|]+")) reason = "unknown";
    LOG.debugf("[WALLET-RESOLVER-DIAG] exit=%d, reason=%s, lines=%d, capped=%s, dht=%s",
        exit, reason.replace(',', '|'), Math.min(totalLines, MAX_DIAGNOSTIC_LINES),
        totalLines > MAX_DIAGNOSTIC_LINES, sanitizedDhtSummaries(output));
  }

  private static String sanitizedDhtSummaries(String output) {
    java.util.Map<String, DhtLookupSummary> summaries = new java.util.TreeMap<>();
    for (String line : output.split("\\R", -1)) {
      if (!line.startsWith("DHT_LOOKUP_SUMMARY ")) continue;
      DhtLookupSummary summary = parseDhtLookupSummary(line);
      if (summary == null || summaries.putIfAbsent(summary.stage(), summary) != null) return "invalid";
    }
    if (summaries.isEmpty()) return "none";
    return summaries.values().stream().map(DhtLookupSummary::sanitized)
        .collect(java.util.stream.Collectors.joining("|"));
  }

  private static boolean isPeerHandshakeFailure(String line) {
    String prefix = "failed to upgrade security for peer ";
    String secureSuffix = ": handshake failed when upgrading to secure connection";
    String shortSuffix = ": handshake failed";
    if (!line.startsWith(prefix)) return false;
    String peer = line.substring(prefix.length(),
        line.endsWith(secureSuffix) ? line.length() - secureSuffix.length()
            : line.endsWith(shortSuffix) ? line.length() - shortSuffix.length() : 0);
    return (line.endsWith(secureSuffix) || line.endsWith(shortSuffix))
        && peer.startsWith("12D3Koo") && peer.length() == 52
        && peer.chars().allMatch(character -> "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            .indexOf(character) >= 0);
  }

  static boolean terminateProcessWithinGrace(Process process) throws InterruptedException {
    try {
      process.destroyForcibly();
      return process.waitFor(FORCED_TERMINATION_WAIT_SECONDS, TimeUnit.SECONDS);
    } catch (RuntimeException terminationFailure) {
      return false;
    }
  }

  static String exactRegistryObjectKeyHex(String identityId) {
    try {
      return java.util.HexFormat.of().formatHex(
          java.security.MessageDigest.getInstance("SHA-256").digest(identityId.getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException unavailable) {
      throw new IllegalStateException("SHA-256 is unavailable", unavailable);
    }
  }

  static boolean isConfirmedIdentityNotFound(String output, String expectedObjectKeyHex) {
    if (expectedObjectKeyHex == null || !expectedObjectKeyHex.matches("[0-9a-fA-F]{64}")) {
      return false;
    }
    String[] lines = output.split("\\R", -1);
    int terminalLine = lines.length - 1;
    while (terminalLine >= 0 && lines[terminalLine].isEmpty()) terminalLine--;
    if (terminalLine < 1 || !"not found".equals(lines[terminalLine])) return false;
    boolean sawRegistryMiss = false;
    DhtLookupSummary getValueSummary = null;
    DhtLookupSummary remoteSummary = null;
    for (int index = 0; index < terminalLine; index++) {
      String line = lines[index];
      if (isKnownDialWarning(line)) return false;
      DhtLookupSummary summary = parseDhtLookupSummary(line);
      if (summary != null) {
        if (!summary.isCleanAbsence()) return false;
        if (summary.stage().equals("get_value")) {
          if (getValueSummary != null) return false;
          getValueSummary = summary;
        } else {
          if (remoteSummary != null) return false;
          remoteSummary = summary;
        }
        continue;
      }
      if (isRegistryIdentityMiss(line)) {
        if (sawRegistryMiss
            || !expectedObjectKeyHex.equalsIgnoreCase(line.substring(REGISTRY_MISS_PREFIX.length()))) {
          return false;
        }
        sawRegistryMiss = true;
        continue;
      }
      return false;
    }
    return sawRegistryMiss && getValueSummary != null && remoteSummary != null;
  }

  private static DhtLookupSummary parseDhtLookupSummary(String line) {
    Matcher matcher = DHT_LOOKUP_SUMMARY_PATTERN.matcher(line);
    if (!matcher.matches()) return null;
    try {
      return new DhtLookupSummary(
          matcher.group(1),
          Integer.parseInt(matcher.group(2)),
          Integer.parseInt(matcher.group(3)),
          Integer.parseInt(matcher.group(4)),
          Integer.parseInt(matcher.group(5)),
          Integer.parseInt(matcher.group(6)));
    } catch (NumberFormatException invalidCount) {
      return null;
    }
  }

  private record DhtLookupSummary(
      String stage, int attempts, int empty, int failed, int timeouts, int incomplete) {
    boolean isCleanAbsence() {
      return attempts > 0 && empty == attempts && failed == 0 && timeouts == 0 && incomplete == 0;
    }

    String sanitized() {
      return stage + ":" + attempts + "/" + empty + "/" + failed + "/" + timeouts + "/" + incomplete;
    }
  }

  private static boolean isRegistryIdentityMiss(String line) {
    if (!line.startsWith(REGISTRY_MISS_PREFIX)) return false;
    String objectKey = line.substring(REGISTRY_MISS_PREFIX.length());
    if (objectKey.length() != IDENTITY_OBJECT_KEY_HEX_LENGTH) return false;
    return objectKey.chars().allMatch(character -> Character.digit(character, 16) >= 0);
  }

  static String extractIdentityJson(String output) {
    String[] lines = output.split("\\R", -1);
    int start = -1;
    int diagnosticLines = 0;
    for (int index = 0; index < lines.length; index++) {
      String line = lines[index];
      if (line.stripLeading().startsWith("{")) {
        start = index;
        break;
      }
      if (!line.isBlank()) {
        if (!isRecognizedDhtDiagnostic(line) || ++diagnosticLines > MAX_DIAGNOSTIC_LINES) {
          throw new IllegalArgumentException("unrecognized text before identity JSON");
        }
      }
    }
    if (start < 0) throw new IllegalArgumentException("identity JSON is missing");
    StringBuilder json = new StringBuilder();
    int depth = 0;
    boolean quoted = false;
    boolean escaped = false;
    int endLine = -1;
    for (int index = start; index < lines.length; index++) {
      String line = lines[index];
      if (index > start) json.append("\n");
      json.append(line);
      if (index > start && !line.isBlank() && isRecognizedDhtDiagnostic(line) && !quoted && depth > 0) {
        continue;
      }
      for (int offset = 0; offset < line.length(); offset++) {
        char current = line.charAt(offset);
        if (quoted) {
          if (escaped) escaped = false;
          else if (current == '\\') escaped = true;
          else if (current == '"') quoted = false;
        } else if (current == '"') quoted = true;
        else if (current == '{') depth++;
        else if (current == '}') depth--;
      }
      if (depth == 0 && !quoted) { endLine = index; break; }
    }
    if (endLine < 0) throw new IllegalArgumentException("identity JSON is incomplete");
    diagnosticLines = 0;
    for (int index = endLine + 1; index < lines.length; index++) {
      if (!lines[index].isBlank()) {
        if (!isRecognizedDhtDiagnostic(lines[index]) || ++diagnosticLines > MAX_DIAGNOSTIC_LINES) {
          throw new IllegalArgumentException("unrecognized text after identity JSON");
        }
      }
    }
    String clean = removeInterleavedDhtDiagnostics(json.toString());
    return clean;
  }

  private static String removeInterleavedDhtDiagnostics(String json) {
    String[] lines = json.split("\\R", -1);
    StringBuilder cleaned = new StringBuilder();
    boolean inside = false;
    int braces = 0;
    boolean inString = false;
    boolean escape = false;
    for (String line : lines) {
      boolean diagnostic = isRecognizedDhtDiagnostic(line);
      if (diagnostic && inside && braces > 0 && !inString) continue;
      if (cleaned.length() > 0) cleaned.append('\n');
      cleaned.append(line);
      for (int index = 0; index < line.length(); index++) {
        char current = line.charAt(index);
        if (inString) {
          if (escape) escape = false;
          else if (current == '\\') escape = true;
          else if (current == '"') inString = false;
        } else if (current == '"') inString = true;
        else if (current == '{') { braces++; inside = true; }
        else if (current == '}') braces--;
      }
    }
    return cleaned.toString();
  }

  private static String stripRecognizedDhtDiagnostics(String output) {
    String[] lines = output.split("\\R", -1);
    int firstResultLine = 0;
    while (firstResultLine < lines.length && isRecognizedDhtDiagnostic(lines[firstResultLine])) {
      firstResultLine++;
    }
    String remainder = String.join("\n", java.util.Arrays.copyOfRange(lines, firstResultLine, lines.length)).trim();
    if (!remainder.startsWith("{")) return remainder;
    int depth = 0;
    boolean inString = false;
    boolean escaped = false;
    for (int index = 0; index < remainder.length(); index++) {
      char character = remainder.charAt(index);
      if (inString) {
        if (escaped) escaped = false;
        else if (character == '\\') escaped = true;
        else if (character == '"') inString = false;
      } else if (character == '"') inString = true;
      else if (character == '{') depth++;
      else if (character == '}' && --depth == 0) {
        String trailing = remainder.substring(index + 1).trim();
        for (String diagnostic : trailing.split("\\R", -1)) {
          if (!diagnostic.isBlank() && !isRecognizedDhtDiagnostic(diagnostic)) return remainder;
        }
        return remainder.substring(0, index + 1);
      }
    }
    return remainder;
  }

  private static boolean isRecognizedDhtDiagnostic(String line) {
    if (parseDhtLookupSummary(line) != null) return true;
    if (line.startsWith(DIALING_PREFIX) || line.startsWith(CONNECTED_PREFIX)) {
      String endpoint = line.substring(line.indexOf(' ') + 1);
      return !endpoint.isBlank();
    }
    if (isKnownDialWarning(line) || isRegistryIdentityMiss(line)) return true;
    String prefix = "failed to upgrade security for peer ";
    String secureSuffix = ": handshake failed when upgrading to secure connection";
    String shortSuffix = ": handshake failed";
    if (!line.startsWith(prefix)) return false;
    String peer = line.substring(prefix.length(),
        line.endsWith(secureSuffix) ? line.length() - secureSuffix.length()
            : line.endsWith(shortSuffix) ? line.length() - shortSuffix.length() : 0);
    return (line.endsWith(secureSuffix) || line.endsWith(shortSuffix))
        && peer.startsWith("12D3Koo") && peer.length() == 52
        && peer.chars().allMatch(character -> "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            .indexOf(character) >= 0);
  }

  @com.fasterxml.jackson.annotation.JsonIgnoreProperties(ignoreUnknown = true)
  private static final class IdentityResolutionResult {
    @com.fasterxml.jackson.annotation.JsonProperty("identifier") public String identifier;
    @com.fasterxml.jackson.annotation.JsonProperty("owner_name_hex") public String ownerNameHex;
    @com.fasterxml.jackson.annotation.JsonProperty("owner_public_key_hex") public String ownerPublicKeyHex;
    @com.fasterxml.jackson.annotation.JsonProperty("seq") public long seq;
  }

  private static boolean isKnownDialWarning(String line) {
    if (!line.startsWith(DIAL_WARNING_PREFIX) || !line.endsWith(DIAL_WARNING_SUFFIX)) return false;
    String endpoint = line.substring(DIAL_WARNING_PREFIX.length(), line.length() - DIAL_WARNING_SUFFIX.length());
    return !endpoint.isBlank() && endpoint.chars().noneMatch(Character::isWhitespace);
  }

  private static final class BoundedOutput {
    private final int maxBytes;
    private final java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
    private final AtomicBoolean overflow = new AtomicBoolean();
    BoundedOutput(int maxBytes) { this.maxBytes = maxBytes; }
    void drain(java.io.InputStream input) {
      try (input) {
        byte[] buffer = new byte[1024]; int count;
        while ((count = input.read(buffer)) >= 0) {
          synchronized (output) {
            if (output.size() + count > maxBytes) { overflow.set(true); return; }
            output.write(buffer, 0, count);
          }
        }
      } catch (Exception ignored) { overflow.set(true); }
    }
    boolean overflowed() { return overflow.get(); }
    String text() { synchronized (output) { return output.toString(StandardCharsets.UTF_8).trim(); } }
  }

  public static final class IdentityResolutionException extends Exception {
    private final boolean processMayStillRun;
    IdentityResolutionException(String message) { this(message, null, false); }
    IdentityResolutionException(String message, Throwable cause) { this(message, cause, false); }
    IdentityResolutionException(String message, boolean processMayStillRun) {
      this(message, null, processMayStillRun);
    }
    private IdentityResolutionException(String message, Throwable cause, boolean processMayStillRun) {
      super(message, cause);
      this.processMayStillRun = processMayStillRun;
    }
    boolean processMayStillRun() { return processMayStillRun; }
  }
}
