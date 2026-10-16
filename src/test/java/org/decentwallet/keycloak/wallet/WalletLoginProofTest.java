package org.decentwallet.keycloak.wallet;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class WalletLoginProofTest {
  private static final String CHALLENGE = "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ";
  private static final String SIGNATURE = "58H-hSanLm-pv_99yMMEQdjV0Oy5KjQ33PPFYrnbM72587nHD8eHBM9vjjIXUqyQbWFz63FhtjyiDMBea5x3Aw";
  private static final String PUBLIC_KEY = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
  private static final String VALID_VECTOR = "/wallet-login-v1/vectors/valid-basic.json";
  private static final String NEGATIVE_VECTOR = "/wallet-login-v1/vectors/negative.json";

  private static String digestHex(String text) throws Exception {
    byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
        .digest(text.getBytes(StandardCharsets.UTF_8));
    return java.util.HexFormat.of().formatHex(digest);
  }

  private static String readFixture(String resource) throws Exception {
    try (var input = WalletLoginProofTest.class.getResourceAsStream(resource)) {
      if (input == null) throw new IllegalStateException("missing bundled fixture " + resource);
      return new String(input.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static Map<?, ?> readJson(String json) throws Exception {
    ObjectMapper mapper = new ObjectMapper(JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    return mapper.readValue(json, Map.class);
  }

  private static WalletLoginProof proofFromVector() throws Exception {
    String json = readFixture(VALID_VECTOR);
    int start = json.indexOf("\"proof\":");
    start = json.indexOf('{', start);
    int end = json.lastIndexOf('}', json.indexOf("\"expected\"", start));
    return WalletLoginProof.parse(json.substring(start, end + 1).getBytes(StandardCharsets.UTF_8));
  }

  private static String proofJson(String profile, String identity, String challenge, String signature) {
    return "{\"signature\":\"" + signature + "\",\"identity_id\":\"" + identity
        + "\",\"profile\":\"" + profile + "\",\"challenge\":\"" + challenge + "\"}";
  }

  @Test
  void walletLoginVectorFixturesAreBundledOnTheTestClasspath() {
    assertNotNull(getClass().getResource("/wallet-login-v1/manifest.json"));
    assertNotNull(getClass().getResource("/wallet-login-v1/vectors/valid-basic.json"));
    assertNotNull(getClass().getResource("/wallet-login-v1/vectors/negative.json"));
  }

  @Test
  void vendoredVectorsMatchHashesDeclaredByTheirUpstreamManifest() throws Exception {
    Map<?, ?> manifest = readJson(readFixture("/wallet-login-v1/manifest.json"));
    Map<?, ?> digests = (Map<?, ?>) manifest.get("sha256");
    assertEquals(digestHex(readFixture(VALID_VECTOR)), digests.get("vectors/valid-basic.json"));
    assertEquals(digestHex(readFixture(NEGATIVE_VECTOR)), digests.get("vectors/negative.json"));
  }

  @Test
  void parsesSharedVectorAndCanonicalizesSignedMembers() throws Exception {
    WalletLoginProof proof = proofFromVector();
    assertEquals(WalletLoginProof.PROFILE, proof.profile());
    assertEquals("mailto:alice@example.org", proof.identityId());
    assertEquals(CHALLENGE, proof.challenge());
    assertEquals("{\"challenge\":\"" + CHALLENGE + "\",\"identity_id\":\"mailto:alice@example.org\",\"profile\":\"decent-wallet-login-v1\"}", new String(proof.signedBytes(), StandardCharsets.UTF_8));
    assertEquals(64, proof.signature().length);
    Map<?, ?> vector = readJson(readFixture(VALID_VECTOR));
    assertEquals("decent-wallet-login-v1", vector.get("protocol"));
    assertEquals("valid-basic", vector.get("vector_id"));
    assertEquals(CHALLENGE, vector.get("challenge"));
    assertEquals(SIGNATURE, vector.get("signature_b64url"));
    assertEquals(new String(proof.signedBytes(), StandardCharsets.UTF_8), vector.get("signed_bytes_utf8"));
    assertEquals(proof.identityId(), vector.get("identity_id"));
    assertTrue(((String) vector.get("challenge_preimage")).contains("nonce_hex"));
  }

  @Test
  void verifiesEd25519VectorSignatureAgainstResolvedCurrentKey() throws Exception {
    Map<?, ?> vector = readJson(readFixture(VALID_VECTOR));
    assertEquals(PUBLIC_KEY, vector.get("public_key_b64url"));
    WalletLoginProof proof = proofFromVector();
    byte[] publicKey = Base64.getUrlDecoder().decode(PUBLIC_KEY);
    assertTrue(new WalletLoginVerifier().verify(proof, CHALLENGE, publicKey));
  }

  @Test
  void rejectsWrongResolvedKeyAndChangedChallenge() throws Exception {
    WalletLoginProof proof = proofFromVector();
    byte[] wrongKey = new byte[32];
    assertFalse(new WalletLoginVerifier().verify(proof, CHALLENGE, wrongKey));
    assertFalse(new WalletLoginVerifier().verify(proof, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Base64.getUrlDecoder().decode(PUBLIC_KEY)));
  }

  @Test
  void rejectsWrongProfileDuplicateMembersAndUnknownMembers() {
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(proofJson("decent-wallet-login-v0", "mailto:alice@example.org", CHALLENGE, SIGNATURE).getBytes(StandardCharsets.UTF_8)));
    String duplicate = "{\"profile\":\"decent-wallet-login-v1\",\"profile\":\"decent-wallet-login-v1\",\"challenge\":\"" + CHALLENGE + "\",\"identity_id\":\"mailto:alice@example.org\",\"signature\":\"" + SIGNATURE + "\"}";
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(duplicate.getBytes(StandardCharsets.UTF_8)));
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse((proofJson(WalletLoginProof.PROFILE, "mailto:alice@example.org", CHALLENGE, SIGNATURE).substring(0, proofJson(WalletLoginProof.PROFILE, "mailto:alice@example.org", CHALLENGE, SIGNATURE).length()-1) + ",\"extra\":\"x\"}").getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void rejectsMissingMemberAndWrongLengthSignature() throws Exception {
    Map<?, ?> negative = readJson(
        readFixture(NEGATIVE_VECTOR));
    assertEquals(10, ((java.util.List<?>) negative.get("vectors")).size());
    String valid = proofJson(WalletLoginProof.PROFILE, "mailto:alice@example.org", CHALLENGE, SIGNATURE);
    String missingIdentity = valid.replace(",\"identity_id\":\"mailto:alice@example.org\"", "");
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(missingIdentity.getBytes(StandardCharsets.UTF_8)));
    byte[] decoded = Base64.getUrlDecoder().decode(SIGNATURE);
    String shortSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.Arrays.copyOf(decoded, 63));
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(proofJson(WalletLoginProof.PROFILE,
        "mailto:alice@example.org", CHALLENGE, shortSignature).getBytes(StandardCharsets.UTF_8)));
    int exercised = 0;
    byte[] publicKey = Base64.getUrlDecoder().decode(PUBLIC_KEY);
    for (Object raw : (java.util.List<?>) negative.get("vectors")) {
      Map<?, ?> vector = (Map<?, ?>) raw;
      assertNotNull(vector.get("id"));
      assertNotNull(vector.get("mutation"));
      assertNotNull(vector.get("expected"));
      String id = (String) vector.get("id");
      switch (id) {
        case "wrong-profile" -> assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(
            proofJson("decent-wallet-login-v0", "mailto:alice@example.org", CHALLENGE, SIGNATURE).getBytes(StandardCharsets.UTF_8)));
        case "challenge-tampered" -> {
          String changedChallenge = "A" + CHALLENGE.substring(1);
          WalletLoginProof mutated = WalletLoginProof.parse(proofJson(WalletLoginProof.PROFILE,
              "mailto:alice@example.org", changedChallenge, SIGNATURE).getBytes(StandardCharsets.UTF_8));
          assertFalse(new WalletLoginVerifier().verify(mutated, changedChallenge, publicKey));
        }
        case "identifier-case-changed" -> assertFalse(new WalletLoginVerifier().verify(
            WalletLoginProof.parse(proofJson(WalletLoginProof.PROFILE, "mailto:Alice@example.org", CHALLENGE, SIGNATURE).getBytes(StandardCharsets.UTF_8)), CHALLENGE, publicKey));
        case "identifier-unicode-normalized" -> {
          String exactIdentifier = "mailto:cafe" + '\u0301' + "@example.org";
          WalletLoginProof mutated = WalletLoginProof.parse(proofJson(
              WalletLoginProof.PROFILE, exactIdentifier, CHALLENGE, SIGNATURE).getBytes(StandardCharsets.UTF_8));
          assertEquals(exactIdentifier, mutated.identityId());
          assertTrue(new String(mutated.signedBytes(), StandardCharsets.UTF_8).contains(exactIdentifier));
          assertFalse(new WalletLoginVerifier().verify(mutated, CHALLENGE, publicKey));
        }
        case "signature-tampered" -> {
          byte[] damaged = Base64.getUrlDecoder().decode(SIGNATURE); damaged[0] ^= 1;
          assertFalse(new WalletLoginVerifier().verify(WalletLoginProof.parse(proofJson(WalletLoginProof.PROFILE,
              "mailto:alice@example.org", CHALLENGE, Base64.getUrlEncoder().withoutPadding().encodeToString(damaged)).getBytes(StandardCharsets.UTF_8)), CHALLENGE, publicKey));
        }
        case "signature-wrong-length" -> assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(
            proofJson(WalletLoginProof.PROFILE, "mailto:alice@example.org", CHALLENGE, shortSignature).getBytes(StandardCharsets.UTF_8)));
        case "signature-padding" -> assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(
            proofJson(WalletLoginProof.PROFILE, "mailto:alice@example.org", CHALLENGE, SIGNATURE + "=").getBytes(StandardCharsets.UTF_8)));
        case "proof-extra-member" -> assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(
            (valid.substring(0, valid.length()-1) + ",\"extra\":\"x\"}").getBytes(StandardCharsets.UTF_8)));
        case "proof-missing-member" -> assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(missingIdentity.getBytes(StandardCharsets.UTF_8)));
        case "proof-duplicate-member" -> assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(
            valid.replace("\"identity_id\":\"mailto:alice@example.org\"", "\"identity_id\":\"mailto:alice@example.org\",\"identity_id\":\"mailto:alice@example.org\"").getBytes(StandardCharsets.UTF_8)));
        default -> throw new AssertionError("unhandled negative vector: " + id);
      }
      exercised++;
    }
    assertEquals(10, exercised);
    String nestedUnknown = valid.replace("\"signature\":\"", "\"extra\":{\"nested\":1},\"signature\":\"");
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(nestedUnknown.getBytes(StandardCharsets.UTF_8)));
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse("not-json".getBytes(StandardCharsets.UTF_8)));
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(new byte[] {(byte) 0xc3, 0x28}));
  }

  @Test
  void rejectsBadEncodingsAndBodySizes() {
    String padded = proofJson(WalletLoginProof.PROFILE, "mailto:alice@example.org", CHALLENGE, SIGNATURE + "=");
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(padded.getBytes(StandardCharsets.UTF_8)));
    byte[] huge = new byte[8193];
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(huge));
    StringBuilder manyMembers = new StringBuilder("{\"profile\":\"decent-wallet-login-v1\"");
    for (int i = 0; i < 2000; i++) manyMembers.append(",\"x\":\"y\"");
    manyMembers.append('}');
    assertThrows(InvalidProof.class, () -> WalletLoginProof.parse(manyMembers.toString().getBytes(StandardCharsets.UTF_8)));
    assertFalse(WalletLoginVerifier.challengeMatches(CHALLENGE, CHALLENGE + "="));
  }

  @Test
  void identityStringIsSignedExactlyWithoutUnicodeNormalization() throws Exception {
    String altered = proofJson(WalletLoginProof.PROFILE, "mailto:Alice@example.org", CHALLENGE, SIGNATURE);
    WalletLoginProof proof = WalletLoginProof.parse(altered.getBytes(StandardCharsets.UTF_8));
    assertNotEquals(new String(proofFromVector().signedBytes(), StandardCharsets.UTF_8), new String(proof.signedBytes(), StandardCharsets.UTF_8));
    assertFalse(new WalletLoginVerifier().verify(proof, CHALLENGE, Base64.getUrlDecoder().decode(PUBLIC_KEY)));
  }
}
