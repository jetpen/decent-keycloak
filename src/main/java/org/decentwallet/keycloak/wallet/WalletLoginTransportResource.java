package org.decentwallet.keycloak.wallet;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.io.IOException;
import java.io.InputStream;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@Produces(MediaType.APPLICATION_JSON)
public final class WalletLoginTransportResource implements RealmResourceProvider {
  public static final String EXTENSION_ID = "decent-wallet-login";
  @Context private UriInfo uriInfo;
  private KeycloakSession session;
  private WalletLoginTransportHandler handler;
  private String idpOrigin;
  private String walletOrigin;

  private UriInfo uriInfo() { return uriInfo; }

  private String walletOrigin() { return walletOrigin; }

  public WalletLoginTransportResource() { }

  void configure(KeycloakSession session, WalletLoginTransportHandler handler, String idpOrigin) {
    this.session = session;
    this.handler = handler;
    this.idpOrigin = idpOrigin;
    this.walletOrigin = session.getContext().getRealm().getAttribute(
        WalletLoginTransportResourceFactory.KEY_WALLET_ORIGIN);
  }

  @Override public Object getResource() { return this; }
  @Override public void close() {}

  @GET
  @Path("v1/transactions/health")
  @Produces(MediaType.TEXT_PLAIN)
  public Response routeProbe() {
    return Response.ok("decent-wallet-login").header("Cache-Control", "no-store").build();
  }

  @GET
  @Path("v1/transactions/{handle}")
  @Produces(MediaType.APPLICATION_JSON)
  public Response transactionGet(@PathParam("handle") String handle,
      @HeaderParam("Origin") String origin,
      @HeaderParam("Sec-Fetch-Site") String fetchSite,
      @HeaderParam("Sec-Fetch-Mode") String fetchMode,
      @HeaderParam("Sec-Fetch-Dest") String fetchDest) {
    return responseWithCors(handler.getChallenge(handle, origin, fetchSite,
        fetchMode, fetchDest, idpOrigin), origin);
  }

  @POST
  @Path("v1/transactions/{handle}")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response transactionPost(@PathParam("handle") String handle,
      @HeaderParam("Origin") String origin,
      @HeaderParam("Sec-Fetch-Site") String fetchSite,
      @HeaderParam("Sec-Fetch-Mode") String fetchMode,
      @HeaderParam("Sec-Fetch-Dest") String fetchDest,
      @HeaderParam("Content-Type") String contentType,
      @HeaderParam("X-Decent-CSRF") String csrf,
      InputStream body) {
    final byte[] boundedBody;
    try {
      boundedBody = readBoundedBody(body);
    } catch (IOException malformedBody) {
      return responseWithCors(WalletLoginTransportHandler.HttpResult.empty(400), origin);
    }
    if (boundedBody == null) {
      return responseWithCors(WalletLoginTransportHandler.HttpResult.empty(413), origin);
    }
    return responseWithCors(handler.submitProof(handle, origin, fetchSite, fetchMode, fetchDest,
        contentType, csrf, boundedBody, idpOrigin), origin);
  }

  @GET
  @Path("v1/transactions/{handle}/status")
  @Produces(MediaType.APPLICATION_JSON)
  public Response status(@PathParam("handle") String handle,
      @HeaderParam("Origin") String origin,
      @HeaderParam("Sec-Fetch-Site") String fetchSite,
      @HeaderParam("Sec-Fetch-Mode") String fetchMode,
      @HeaderParam("Sec-Fetch-Dest") String fetchDest,
      @HeaderParam("X-Decent-CSRF") String csrf) {
    var realm = session.getContext().getRealm();
    if (realm == null || uriInfo() == null) return notFound();
    String requestedClientId = uriInfo().getQueryParameters().getFirst("client_id");
    String tabId = uriInfo().getQueryParameters().getFirst("tab_id");
    if (requestedClientId == null || tabId == null) return notFound();
    var client = realm.getClientByClientId(requestedClientId);
    if (client == null) return notFound();
    AuthenticationSessionManager sessions = new AuthenticationSessionManager(session);
    var auth = sessions.getCurrentAuthenticationSession(realm, client, tabId);
    if (auth == null || auth.getClient() == null || auth.getParentSession() == null
        || !client.getId().equals(auth.getClient().getId()) || !tabId.equals(auth.getTabId())
        || !requestedClientId.equals(auth.getAuthNote("decent.wallet.client-id"))) return notFound();
    String initialRedirect = auth.getAuthNote("decent.wallet.redirect_uri");
    if (initialRedirect == null || !initialRedirect.equals(auth.getRedirectUri())) return notFound();
    String boundOrigin = auth.getAuthNote("decent.wallet.origin");
    if (boundOrigin == null || !idpOrigin.equals(boundOrigin) || initialRedirect == null
        || !handle.equals(auth.getAuthNote("decent.wallet.handle"))) {
      return notFound();
    }
    var binding = new WalletLoginTransactionStore.Binding(realm.getId(), client.getId(),
        auth.getParentSession().getId(), auth.getTabId(), initialRedirect, boundOrigin);
    var status = handler.getStatus(handle, origin, fetchSite, fetchMode, fetchDest, csrf, idpOrigin, binding);
    if (status.status() == 200 && "accepted".equals(status.body().get("status"))) {
      String callback = auth.getAuthNote("decent.wallet.callback");
      if (callback == null || callback.isBlank() || !callback.startsWith(idpOrigin + "/"))
        return notFound();
      status = new WalletLoginTransportHandler.HttpResult(200,
          java.util.Map.of("status", "accepted", "callback", callback), status.headers());
    }
    return responseWithCors(status, origin);
  }

  @OPTIONS
  @Path("v1/transactions/{handle}")
  public Response preflight(@PathParam("handle") String handle,
      @HeaderParam("Origin") String origin,
      @HeaderParam("Sec-Fetch-Site") String fetchSite,
      @HeaderParam("Sec-Fetch-Mode") String fetchMode,
      @HeaderParam("Sec-Fetch-Dest") String fetchDest,
      @HeaderParam("Access-Control-Request-Method") String method,
      @HeaderParam("Access-Control-Request-Headers") String headers) {
    if (!validPreflightRequest(origin, handler.allowsWalletOrigin(origin), method, headers,
        fetchSite, fetchMode, fetchDest)) {
      return Response.status(403).header("Cache-Control", "no-store").build();
    }
    String allowedHeaders = allowedPreflightHeaders(method, headers);
    return Response.noContent().header("Access-Control-Allow-Origin", origin)
        .header("Access-Control-Allow-Methods", method)
        .header("Access-Control-Allow-Headers", allowedHeaders)
        .header("Access-Control-Max-Age", "300")
        .header("Access-Control-Allow-Credentials", "false").header("Vary", "Origin").build();
  }

  static String allowedPreflightHeaders(String method, String headers) {
    return switch (method) {
      case "GET" -> headers == null || headers.isBlank() ? "" : "Accept";
      case "POST" -> "Content-Type, X-Decent-CSRF";
      default -> throw new IllegalArgumentException("method has no CORS allowlist");
    };
  }

  static boolean validPreflightRequest(String origin, boolean configuredOriginMatches,
      String method, String headers) {
    java.util.Set<String> allowedHeaders = java.util.Arrays.stream(
        headers == null ? new String[0] : headers.toLowerCase(java.util.Locale.ROOT).split(","))
        .map(String::trim).filter(value -> !value.isEmpty())
        .collect(java.util.stream.Collectors.toSet());
    boolean headersAllowed = allowedHeaders.stream()
        .allMatch(value -> value.equals("accept") || value.equals("content-type") || value.equals("x-decent-csrf"));
    boolean csrf = allowedHeaders.contains("x-decent-csrf");
    boolean contentType = allowedHeaders.contains("content-type");
    boolean getAllowed = allowedHeaders.isEmpty() || allowedHeaders.equals(java.util.Set.of("accept"));
    boolean postAllowed = csrf && contentType && allowedHeaders.size() == 2;
    return origin != null && configuredOriginMatches && headersAllowed
        && (("GET".equals(method) && getAllowed) || ("POST".equals(method) && postAllowed));
  }

  static boolean validPreflightRequest(String origin, boolean configuredOriginMatches,
      String method, String headers, String fetchSite, String fetchMode, String fetchDest) {
    return validPreflightRequest(origin, configuredOriginMatches, method, headers)
        && validFetchMetadata(fetchSite, fetchMode, fetchDest);
  }

  static boolean validFetchMetadata(String fetchSite, String fetchMode, String fetchDest) {
    return ("cross-site".equals(fetchSite) || "same-site".equals(fetchSite)
        || "same-origin".equals(fetchSite))
        && "cors".equals(fetchMode) && "empty".equals(fetchDest);
  }

  private Response responseWithCors(WalletLoginTransportHandler.HttpResult result, String origin) {
    Response.ResponseBuilder builder = Response.fromResponse(response(result));
    if (origin != null && handler.allowsWalletOrigin(origin)) {
      builder.header("Access-Control-Allow-Origin", origin)
          .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
          .header("Access-Control-Allow-Headers", "Content-Type, X-Decent-CSRF")
          .header("Access-Control-Allow-Credentials", "false")
          .header("Vary", "Origin");
    }
    return builder.build();
  }

  static byte[] readBoundedBody(InputStream body) throws IOException {
    if (body == null) return null;
    byte[] bytes = body.readNBytes(WalletLoginTransportHandler.MAX_PROOF_BYTES + 1);
    return bytes.length > WalletLoginTransportHandler.MAX_PROOF_BYTES ? null : bytes;
  }

  private static Response notFound() { return Response.status(404).build(); }

  private static Response response(WalletLoginTransportHandler.HttpResult result) {
    Response.ResponseBuilder builder = Response.status(result.status());
    result.headers().forEach(builder::header);
    if (!result.body().isEmpty()) builder.entity(result.body());
    return builder.build();
  }
}
