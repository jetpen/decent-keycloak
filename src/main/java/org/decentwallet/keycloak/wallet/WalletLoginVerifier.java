package org.decentwallet.keycloak.wallet;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

/** Pure proof verification; current Identity key resolution belongs to the caller. */
public final class WalletLoginVerifier {
  private static final byte[] ED25519_X509_PREFIX = new byte[] {
      0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
  };
  private static final Pattern BASE64URL_32 = Pattern.compile("[A-Za-z0-9_-]{43}");

  public boolean verify(WalletLoginProof proof, String expectedChallenge, byte[] currentPublicKey) {
    if (proof == null || currentPublicKey == null || currentPublicKey.length != 32
        || !challengeMatches(expectedChallenge, proof.challenge())
        || !BASE64URL_32.matcher(proof.challenge()).matches()) {
      return false;
    }
    try {
      byte[] challenge = Base64.getUrlDecoder().decode(proof.challenge());
      if (challenge.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(challenge).equals(proof.challenge())) return false;
      byte[] encodedKey = new byte[ED25519_X509_PREFIX.length + currentPublicKey.length];
      System.arraycopy(ED25519_X509_PREFIX, 0, encodedKey, 0, ED25519_X509_PREFIX.length);
      System.arraycopy(currentPublicKey, 0, encodedKey, ED25519_X509_PREFIX.length, currentPublicKey.length);
      PublicKey publicKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encodedKey));
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(publicKey);
      verifier.update(proof.signedBytes());
      return verifier.verify(proof.signature());
    } catch (GeneralSecurityException | IllegalArgumentException ex) {
      return false;
    }
  }

  public static boolean challengeMatches(String expectedChallenge, String proofChallenge) {
    if (expectedChallenge == null || proofChallenge == null
        || !BASE64URL_32.matcher(expectedChallenge).matches()
        || !BASE64URL_32.matcher(proofChallenge).matches()) return false;
    return java.security.MessageDigest.isEqual(
        expectedChallenge.getBytes(StandardCharsets.US_ASCII),
        proofChallenge.getBytes(StandardCharsets.US_ASCII));
  }
}
