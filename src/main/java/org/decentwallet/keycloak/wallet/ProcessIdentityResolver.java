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
    command.add("--identifier");
    command.add(identityId);
    command.add("--host");
    command.add("127.0.0.1");
    command.add("--port");
    command.add(Integer.toString(clientPort));
    for (String peer : bootstrap) { command.add("--bootstrap"); command.add(peer); }

    ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
    builder.environment().clear();
    builder.environment().put("PATH", "/usr/local/bin:/usr/bin:/bin");
    builder.environment().put("LANG", "C.UTF-8");
    Process process = builder.start();
    BoundedOutput output = new BoundedOutput(MAX_OUTPUT_BYTES);
    Thread reader = Thread.ofPlatform().daemon().start(() -> output.drain(process.getInputStream()));
    final boolean finished;
    try {
      finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    } catch (InterruptedException interrupted) {
      boolean terminated = false;
      try { terminated = terminateProcessWithinGrace(process); }
      catch (InterruptedException terminationInterrupted) { interrupted.addSuppressed(terminationInterrupted); }
      Thread.currentThread().interrupt();
      throw new IdentityResolutionException("Identity lookup interrupted", !terminated);
    }
    if (!finished) {
      boolean terminated;
      try { terminated = terminateProcessWithinGrace(process); }
      catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        throw new IdentityResolutionException("Identity lookup termination interrupted", true);
      }
      throw new IdentityResolutionException("Identity lookup timed out", !terminated);
    }
    reader.join(TimeUnit.SECONDS.toMillis(1));
    if (output.overflowed()) throw new IdentityResolutionException("Identity lookup response exceeded limit");
    int exit = process.exitValue();
    String outputText = output.text();
    if (exit == 1 && isConfirmedIdentityNotFound(outputText)) return null;
    if (exit == 3 || stripRecognizedDhtDiagnostics(outputText).startsWith("history unavailable:")) {
      throw new IdentityResolutionException("Identity history unavailable");
    }
    if (exit != 0) throw new IdentityResolutionException("Identity lookup failed");
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
    } catch (IdentityResolutionException e) {
      throw e;
    } catch (Exception e) {
      throw new IdentityResolutionException("Identity lookup result was invalid", e);
    }
  }

  static boolean terminateProcessWithinGrace(Process process) throws InterruptedException {
    try {
      process.destroyForcibly();
      return process.waitFor(FORCED_TERMINATION_WAIT_SECONDS, TimeUnit.SECONDS);
    } catch (RuntimeException terminationFailure) {
      return false;
    }
  }

  static boolean isConfirmedIdentityNotFound(String output) {
    String[] lines = output.split("\\R", -1);
    if (lines.length < 2 || !"not found".equals(lines[lines.length - 1])) return false;
    boolean sawRegistryMiss = false;
    for (int index = 0; index < lines.length - 1; index++) {
      String line = lines[index];
      if (isKnownDialWarning(line)) continue;
      if (isRegistryIdentityMiss(line)) {
        sawRegistryMiss = true;
        continue;
      }
      return false;
    }
    return sawRegistryMiss;
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
