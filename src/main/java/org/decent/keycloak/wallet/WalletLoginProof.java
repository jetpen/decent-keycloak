package org.decent.keycloak.wallet;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.erdtman.jcs.JsonCanonicalizer;

/** Strict wire parsing and RFC 8785 serialization for decent-wallet-login-v1. */
public final class WalletLoginProof {
  public static final String PROFILE = "decent-wallet-login-v1";
  private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");
  private final String profile;
  private final String challenge;
  private final String identityId;
  private final byte[] signature;
  private final byte[] signedBytes;

  private WalletLoginProof(String profile, String challenge, String identityId,
      byte[] signature, byte[] signedBytes) {
    this.profile = profile;
    this.challenge = challenge;
    this.identityId = identityId;
    this.signature = signature.clone();
    this.signedBytes = signedBytes.clone();
  }

  public static WalletLoginProof parse(byte[] json) {
    if (json == null || json.length == 0 || json.length > 8192) {
      throw new InvalidProof("proof body size rejected");
    }
    try {
      String input = strictUtf8(json);
      Map<String, String> fields = parseFourStringMembers(input);
      if (!fields.keySet().equals(Set.of("profile", "challenge", "identity_id", "signature"))) {
        throw new InvalidProof("proof schema rejected");
      }
      String profile = fields.get("profile");
      String challenge = fields.get("challenge");
      String identityId = fields.get("identity_id");
      if (!PROFILE.equals(profile)) throw new InvalidProof("proof profile rejected");
      requireBase64Url(challenge, 32, "challenge");
      requireBase64Url(fields.get("signature"), 64, "signature");
      if (identityId.isEmpty() || identityId.getBytes(StandardCharsets.UTF_8).length > 1024) {
        throw new InvalidProof("identity identifier rejected");
      }
      Map<String, Object> signedObject = new LinkedHashMap<>();
      signedObject.put("profile", profile);
      signedObject.put("challenge", challenge);
      signedObject.put("identity_id", identityId);
      try {
        byte[] signedBytes = new JsonCanonicalizer(toJson(signedObject)).getEncodedUTF8();
        return new WalletLoginProof(profile, challenge, identityId,
            decodeBase64Url(fields.get("signature")), signedBytes);
      } catch (Exception e) {
        if (e instanceof InvalidProof invalid) throw invalid;
        throw new InvalidProof("proof canonicalization rejected", e);
      }
    } catch (InvalidProof e) {
      throw e;
    } catch (RuntimeException e) {
      throw new InvalidProof("proof JSON rejected", e);
    }
  }

  public String profile() { return profile; }
  public String challenge() { return challenge; }
  public String identityId() { return identityId; }
  public byte[] signature() { return signature.clone(); }
  public byte[] signedBytes() { return signedBytes.clone(); }

  private static Map<String, String> parseFourStringMembers(String input) {
    JsonCursor c = new JsonCursor(input);
    c.ws(); c.expect('{'); c.ws();
    Map<String, String> result = new LinkedHashMap<>();
    if (c.peek('}')) throw new InvalidProof("empty proof rejected");
    while (true) {
      c.ws(); String key = c.string();
      if (!Set.of("profile", "challenge", "identity_id", "signature").contains(key)) {
        throw new InvalidProof("unknown proof member");
      }
      if (result.size() == 4) throw new InvalidProof("too many proof members");
      c.ws(); c.expect(':'); c.ws();
      String value = c.string();
      if (result.containsKey(key)) throw new InvalidProof("duplicate proof member");
      result.put(key, value);
      c.ws();
      if (c.peek('}')) { c.expect('}'); break; }
      c.expect(',');
    }
    c.ws();
    if (!c.done()) throw new InvalidProof("trailing JSON data");
    return result;
  }

  private static String toJson(Map<String, Object> values) {
    StringBuilder b = new StringBuilder("{"); boolean first = true;
    for (Map.Entry<String, Object> entry : values.entrySet()) {
      if (!first) b.append(','); first = false;
      b.append(quote(entry.getKey())).append(':').append(quote((String) entry.getValue()));
    }
    return b.append('}').toString();
  }

  private static String quote(String s) {
    StringBuilder b = new StringBuilder("\"");
    for (int i = 0; i < s.length(); i++) {
      char ch = s.charAt(i);
      switch (ch) {
        case '"' -> b.append("\\\"");
        case '\\' -> b.append("\\\\");
        case '\b' -> b.append("\\b");
        case '\f' -> b.append("\\f");
        case '\n' -> b.append("\\n");
        case '\r' -> b.append("\\r");
        case '\t' -> b.append("\\t");
        default -> { if (ch < 0x20) b.append(String.format("\\u%04x", (int) ch)); else b.append(ch); }
      }
    }
    return b.append('"').toString();
  }

  private static void requireBase64Url(String value, int bytes, String field) {
    if (value == null || !BASE64URL.matcher(value).matches()) throw new InvalidProof(field + " encoding rejected");
    byte[] decoded = decodeBase64Url(value);
    if (decoded.length != bytes || !Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)) {
      throw new InvalidProof(field + " encoding rejected");
    }
  }

  private static byte[] decodeBase64Url(String value) {
    try { return Base64.getUrlDecoder().decode(value); }
    catch (IllegalArgumentException e) { throw new InvalidProof("base64url encoding rejected", e); }
  }

  private static String strictUtf8(byte[] input) {
    try {
      return StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
          .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
          .decode(java.nio.ByteBuffer.wrap(input)).toString();
    } catch (java.nio.charset.CharacterCodingException e) {
      throw new InvalidProof("proof UTF-8 rejected", e);
    }
  }

  private static final class JsonCursor {
    private final String s; private int i;
    JsonCursor(String s) { this.s = s; }
    boolean done() { return i == s.length(); }
    void ws() { while (i < s.length() && (s.charAt(i)==' '||s.charAt(i)=='\n'||s.charAt(i)=='\r'||s.charAt(i)=='\t')) i++; }
    boolean peek(char c) { return i < s.length() && s.charAt(i) == c; }
    void expect(char c) { if (!peek(c)) throw new InvalidProof("proof JSON rejected"); i++; }
    String string() {
      expect('"'); StringBuilder b = new StringBuilder();
      while (i < s.length()) {
        char ch=s.charAt(i++);
        if (ch=='"') return b.toString();
        if (ch < 0x20) throw new InvalidProof("proof JSON string rejected");
        if (ch!='\\') { b.append(ch); continue; }
        if (i>=s.length()) throw new InvalidProof("proof JSON escape rejected");
        char e=s.charAt(i++);
        switch(e) {
          case '"','\\','/' -> b.append(e);
          case 'b' -> b.append('\b'); case 'f' -> b.append('\f'); case 'n' -> b.append('\n'); case 'r' -> b.append('\r'); case 't' -> b.append('\t');
          case 'u' -> {
            if (i+4>s.length()) throw new InvalidProof("proof JSON escape rejected");
            int value=0; for(int j=0;j<4;j++){ int d=Character.digit(s.charAt(i++),16); if(d<0) throw new InvalidProof("proof JSON escape rejected"); value=(value<<4)|d; }
            char u=(char)value;
            if (Character.isHighSurrogate(u)) {
              if (i+6>s.length()||s.charAt(i++)!='\\'||s.charAt(i++)!='u') throw new InvalidProof("unpaired JSON surrogate");
              int low=0; for(int j=0;j<4;j++){ int d=Character.digit(s.charAt(i++),16); if(d<0) throw new InvalidProof("proof JSON escape rejected"); low=(low<<4)|d; }
              char l=(char)low; if(!Character.isLowSurrogate(l)) throw new InvalidProof("unpaired JSON surrogate"); b.append(u).append(l);
            } else if (Character.isLowSurrogate(u)) throw new InvalidProof("unpaired JSON surrogate"); else b.append(u);
          }
          default -> throw new InvalidProof("proof JSON escape rejected");
        }
      }
      throw new InvalidProof("unterminated proof JSON string");
    }
  }
}
