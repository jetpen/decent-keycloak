package org.decentwallet.keycloak.wallet;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Set;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.endpoints.request.AuthzEndpointRequestParser;

import org.keycloak.services.Urls;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.context.AuthorizationRequestContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProviderFactory;

/** Validates and binds the signed account action before AuthenticationSession persistence. */
public final class WalletAccountRequestExecutor
    implements ClientPolicyExecutorProvider<WalletAccountRequestExecutor.Configuration> {
  public static final String PROVIDER_ID = "decent-account-request";
  public static final String ACTION_PARAM = "decent_account_action";
  public static final String REQUEST_PARAM = "decent_account_request";
  public static final String AUTH_NOTE_SIGNED = "decent.wallet.account.signed";
  public static final String AUTH_NOTE_INTENT = "decent.wallet.account.intent";
  static final String AUTH_NOTE_ACTION = "decent.wallet.account.action";
  static final String AUTH_NOTE_REQUEST_ID = "decent.wallet.account.request_id";
  static final String AUTH_NOTE_REQUEST_JTI = "decent.wallet.account.jti";
  static final String AUTH_NOTE_EXPIRES = "decent.wallet.account.expires_at";
  static final String SINGLE_USE_PREFIX = "decent-account-request-v1:jti:";
  static final String REQUEST_ID_PREFIX = "decent-account-request-v1:request-id:";
  static String oneUseKey(String prefix, String clientId, String token) {
    return prefix + hex(sha256((clientId + ":" + token).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  }
  private static final String ERROR = OAuthErrorException.INVALID_REQUEST;
  private static final Set<String> CLAIM_IDS = Set.of(
      "urn:decent:account:v1:email", "urn:decent:account:v1:given_name",
      "urn:decent:account:v1:family_name", "urn:decent:account:v1:phone",
      "urn:decent:account:v1:locale");
  private final KeycloakSession session;
  private Configuration configuration;
  private final com.fasterxml.jackson.databind.ObjectMapper strictMapper = new com.fasterxml.jackson.databind.ObjectMapper()
      .enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  public WalletAccountRequestExecutor(KeycloakSession session) {
    this.session = java.util.Objects.requireNonNull(session);
  }

  public static final class Configuration
      extends org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation {
    private Boolean enabled;
    public Boolean getEnabled() { return enabled; }
    public void setEnabled(Boolean enabled) { this.enabled = enabled; }
  }

  public static WalletLoginTransactionStore.Intent intentForAction(String action) {
    if (action == null) throw new IllegalArgumentException("Unsupported account action");
    return switch (action) {
      case "signup" -> WalletLoginTransactionStore.Intent.ACCOUNT_SIGNUP;
      case "signup_recovery" -> WalletLoginTransactionStore.Intent.SIGNUP_RECOVERY;
      default -> throw new IllegalArgumentException("Unsupported account action");
    };
  }

  @Override public Class<Configuration> getExecutorConfigurationClass() { return Configuration.class; }
  @Override public String getProviderId() { return PROVIDER_ID; }
  @Override public void setupConfiguration(Configuration config) { configuration = config; }

  @Override
  public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
    if (context.getEvent() != ClientPolicyEvent.AUTHORIZATION_REQUEST) return;
    if (configuration == null || !Boolean.TRUE.equals(configuration.getEnabled())) {
      throw invalid("The account Request Object policy executor is not enabled");
    }
    authorize((AuthorizationRequestContext) context);
  }

  private void authorize(AuthorizationRequestContext context) throws ClientPolicyException {
    ClientModel client = context.getClient();
    if (client == null) throw invalid("Request Object client is unavailable");
    var params = context.getRequestParameters();
    if (params == null || params.containsKey(ACTION_PARAM) || params.containsKey(REQUEST_PARAM)) {
      throw invalid("Account request fields are allowed only inside the signed Request Object");
    }
    String compactJws = single(params, "request");
    if (compactJws == null) {
      String requestUri = single(params, "request_uri");
      if (requestUri != null) {
        if (!requestUri.toLowerCase(java.util.Locale.ROOT)
            .startsWith("urn:ietf:params:oauth:request_uri:")) {
          throw invalid("Account Request Objects supplied by request_uri must use one-time PAR");
        }
        try {
          var parValues = org.keycloak.protocol.oidc.par.endpoints.request.AuthzEndpointParParser
              .getRequestObject(session, requestUri);
          if (parValues != null) compactJws = parValues.get("request");
        } catch (RuntimeException invalidPar) {
          throw invalid("Pushed account Request Object is unavailable");
        }
      }
    }
    if (compactJws == null || compactJws.isBlank()) {
      throw invalid("A signed account Request Object is required");
    }
    String[] segments = compactJws.split("\\.", -1);
    if (segments.length != 3 || segments[0].isEmpty() || segments[1].isEmpty() || segments[2].isEmpty()) {
      throw invalid("Signed Request Object must be compact JWS");
    }
    JsonNode strictHeader;
    JsonNode strictRequest;
    try {
      strictHeader = strictMapper.readTree(java.util.Base64.getUrlDecoder().decode(segments[0]));
      strictRequest = strictMapper.readTree(java.util.Base64.getUrlDecoder().decode(segments[1]));
    } catch (Exception malformed) {
      throw invalid("Signed Request Object has invalid JSON or duplicate members");
    }
    if (strictHeader == null || !strictHeader.isObject() || strictHeader.size() != 2
        || !"ES256".equals(strictHeader.path("alg").asText())
        || !strictHeader.path("kid").isTextual() || strictHeader.path("kid").asText().isBlank()
        || strictRequest == null || !strictRequest.isObject()) {
      throw invalid("Signed Request Object header or payload is invalid");
    }
    String signedKid = strictHeader.path("kid").asText();
    JsonNode request;
    try {
      // Re-verify the post-parse artifact through Keycloak's client JWT manager. This uses
      // ClientSignatureVerifierProvider and PublicKeyStorageManager (including its cache/JWKS URL).
      request = session.tokens().decodeClientJWT(compactJws, client,
          (jose, registeredClient) -> {
            if (!(jose instanceof org.keycloak.jose.jws.JWSInput input)
                || !"ES256".equals(input.getHeader().getRawAlgorithm())
                || !signedKid.equals(input.getHeader().getKeyId())) {
              throw new IllegalArgumentException("Request Object must use the registered ES256 signer");
            }
          }, JsonNode.class, false);
    } catch (RuntimeException verificationFailure) {
      throw invalid("Request Object signature did not verify with this client");
    }
    if (request == null || !request.isObject() || !request.equals(strictRequest)) {
      throw invalid("Strict Request Object parsing did not match verified claims");
    }
    JsonNode originalRequest = session.getAttribute(AuthzEndpointRequestParser.AUTHZ_REQUEST_OBJECT, JsonNode.class);
    if (originalRequest == null || !request.equals(originalRequest)) {
      throw invalid("Parsed Request Object did not match its verified signed payload");
    }
    String action = requiredText(request.get(ACTION_PARAM), ACTION_PARAM);
    JsonNode extension = request.get(REQUEST_PARAM);
    validateExtension(extension);
    String requestId = extension.get("request_id").textValue();
    String clientId = client.getClientId();
    String issuer = requiredText(request.get("iss"), "iss");
    if (!clientId.equals(issuer) || !clientId.equals(requiredText(request.get("client_id"), "client_id"))) {
      throw invalid("Request Object issuer and client_id must match the registered RP client");
    }
    String exactRealmIssuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(),
        session.getContext().getRealm().getName());
    String audienceValue = requiredText(request.get("aud"), "aud");
    if (!exactRealmIssuer.equals(audienceValue)) {
      throw invalid("Request Object audience must exactly match this realm issuer");
    }
    if (!"ES256".equals(OIDCAdvancedConfigWrapper.fromClientModel(client).getRequestObjectSignatureAlg())) {
      throw invalid("Registered Request Object signature algorithm must be ES256");
    }
    long now = Time.currentTime();
    long iat = integer(request.get("iat"));
    long exp = integer(request.get("exp"));
    boolean moreThan300Seconds = iat <= Long.MAX_VALUE - 300 && exp > iat + 300;
    if (iat > now || exp <= now || exp <= iat || moreThan300Seconds) {
      throw invalid("Request Object iat/exp must be current and no more than 300 seconds apart");
    }
    String jti = requiredText(request.get("jti"), "jti");
    var auth = context.getAuthenticationSession();
    if (auth == null || auth.getClient() == null || !client.getId().equals(auth.getClient().getId())
        || !clientId.equals(auth.getClient().getClientId())) {
      throw invalid("Request Object did not bind to its AuthenticationSession client");
    }
    String requestIdKey = oneUseKey(REQUEST_ID_PREFIX, client.getId(), requestId);
    String jtiKey = oneUseKey(SINGLE_USE_PREFIX, client.getId(), jti);
    var singleUse = session.singleUseObjects();
    if (singleUse.contains(requestIdKey) || singleUse.contains(jtiKey)) {
      throw invalid("Request Object jti/request_id has already been used");
    }
    boolean requestIdClaimed = false;
    try {
      requestIdClaimed = singleUse.putIfAbsent(requestIdKey, exp - now);
      if (!requestIdClaimed || !singleUse.putIfAbsent(jtiKey, exp - now)) {
        if (requestIdClaimed) singleUse.remove(requestIdKey);
        throw invalid("Request Object jti/request_id has already been used");
      }
    } catch (ClientPolicyException replay) {
      throw replay;
    } catch (RuntimeException claimFailure) {
      if (requestIdClaimed) {
        try { singleUse.remove(requestIdKey); }
        catch (RuntimeException ignored) { /* uncertain one-use claims remain fail-closed */ }
      }
      throw invalid("Request Object one-use claim is unavailable");
    }
    auth.setAuthNote(AUTH_NOTE_ACTION, action);
    auth.setAuthNote(AUTH_NOTE_REQUEST_ID, requestId);
    auth.setAuthNote(AUTH_NOTE_REQUEST_JTI, jti);
    auth.setAuthNote(AUTH_NOTE_EXPIRES, Long.toString(exp));
    auth.setAuthNote(AUTH_NOTE_INTENT, intentForAction(action).name());
    auth.setAuthNote(AUTH_NOTE_SIGNED, "true");
  }


  private static String single(jakarta.ws.rs.core.MultivaluedMap<String, String> params, String key)
      throws ClientPolicyException {
    if (params == null) return null;
    List<String> values = params.get(key);
    if (values == null) return null;
    if (values.size() != 1 || values.getFirst() == null || values.getFirst().isBlank()) {
      throw invalid("Request Object transport parameter is repeated or empty");
    }
    return values.getFirst();
  }


  private static void validateExtension(JsonNode extension) throws ClientPolicyException {
    if (extension == null || !extension.isObject() || extension.size() != 4
        || !"decent-account-disclosure-v1".equals(requiredText(extension.get("profile"), "profile"))) {
      throw invalid("Invalid account request extension");
    }
    String requestId = requiredText(extension.get("request_id"), "request_id");
    if (!isCanonicalRequestId(requestId)) throw invalid("Invalid account request ID");
    String purpose = requiredText(extension.get("purpose"), "purpose");
    if (!hasValidUnicodeScalars(purpose)
        || purpose.codePointCount(0, purpose.length()) > 160 || purpose.codePoints().allMatch(Character::isWhitespace)
        || purpose.codePoints().anyMatch(cp -> cp <= 0x1f || cp >= 0x7f && cp <= 0x9f
            || cp >= 0x202a && cp <= 0x202e || cp >= 0x2066 && cp <= 0x2069
            || cp == 0x200e || cp == 0x200f || cp == 0x061c)) {
      throw invalid("Invalid account request purpose");
    }
    JsonNode claims = extension.get("claims");
    if (claims == null || !claims.isArray() || claims.isEmpty() || claims.size() > 16) {
      throw invalid("Account request claims must contain 1 to 16 entries");
    }
    Set<String> seen = new java.util.HashSet<>();
    for (JsonNode claim : claims) {
      if (!claim.isObject() || claim.size() != 2 || !text(claim.get("id"))
          || !claim.get("required").isBoolean() || !CLAIM_IDS.contains(claim.get("id").textValue())
          || !seen.add(claim.get("id").textValue())) {
        throw invalid("Invalid or duplicate account request claim");
      }
    }
  }

  static boolean isCanonicalRequestId(String value) {
    if (value == null || !value.matches("[A-Za-z0-9_-]{22}")) return false;
    try {
      byte[] decoded = java.util.Base64.getUrlDecoder().decode(value);
      return decoded.length == 16
          && java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value);
    } catch (IllegalArgumentException malformed) {
      return false;
    }
  }

  private static boolean hasValidUnicodeScalars(String value) {
    for (int i = 0; i < value.length(); i++) {
      char current = value.charAt(i);
      if (Character.isHighSurrogate(current)) {
        if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) return false;
      } else if (Character.isLowSurrogate(current)) {
        return false;
      }
    }
    return true;
  }

  private static long integer(JsonNode node) throws ClientPolicyException {
    if (node == null || !node.isIntegralNumber() || !node.canConvertToLong()) {
      throw invalid("Request Object timestamp must be an integer");
    }
    return node.longValue();
  }

  private static String requiredText(JsonNode node, String name) throws ClientPolicyException {
    if (node == null || !node.isTextual() || node.textValue().isEmpty()) {
      throw invalid("Missing or invalid " + name);
    }
    return node.textValue();
  }

  private static boolean text(JsonNode node) { return node != null && node.isTextual(); }

  private static ClientPolicyException invalid(String message) {
    return new ClientPolicyException(ERROR, message, jakarta.ws.rs.core.Response.Status.BAD_REQUEST);
  }

  private static byte[] sha256(byte[] input) {
    try { return java.security.MessageDigest.getInstance("SHA-256").digest(input); }
    catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
  }

  private static String hex(byte[] bytes) { return java.util.HexFormat.of().formatHex(bytes); }
  @Override public void close() { }
}
