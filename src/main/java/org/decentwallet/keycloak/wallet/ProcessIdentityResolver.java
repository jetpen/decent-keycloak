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
    String text = stripLeadingDialWarnings(output.text());
    if (exit == 1 && text.startsWith("not found")) return null;
    if (exit == 3 || text.startsWith("history unavailable:")) {
      throw new IdentityResolutionException("Identity history unavailable");
    }
    if (exit != 0) throw new IdentityResolutionException("Identity lookup failed");
    try {
      var node = RESULT_MAPPER.readTree(text);
      String returnedIdentifier = node.path("identifier").asText(null);
      String returnedHex = node.path("owner_name_hex").asText(null);
      String publicKeyHex = node.path("owner_public_key_hex").asText(null);
      long sequence = node.path("seq").asLong(-1);
      if (sequence < 0 || !identityId.equals(returnedIdentifier) || returnedHex == null || publicKeyHex == null
          || !exactHex.equalsIgnoreCase(returnedHex)) {
        throw new IdentityResolutionException("Identity result did not match exact identifier");
      }
      byte[] publicKey = HexFormat.of().parseHex(publicKeyHex);
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

  private static String stripLeadingDialWarnings(String output) {
    String[] lines = output.split("\\R", -1);
    int firstResultLine = 0;
    while (firstResultLine < lines.length && isKnownDialWarning(lines[firstResultLine])) {
      firstResultLine++;
    }
    return String.join("\n", java.util.Arrays.copyOfRange(lines, firstResultLine, lines.length)).trim();
  }

  private static boolean isKnownDialWarning(String line) {
    if (!line.startsWith(DIAL_WARNING_PREFIX) || !line.endsWith(DIAL_WARNING_SUFFIX)) return false;
    String endpoint = line.substring(DIAL_WARNING_PREFIX.length(),
        line.length() - DIAL_WARNING_SUFFIX.length());
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
