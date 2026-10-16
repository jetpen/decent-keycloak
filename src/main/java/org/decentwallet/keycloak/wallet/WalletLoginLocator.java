package org.decentwallet.keycloak.wallet;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/** HTTPS QR locator for the opaque provider-owned transaction. */
public final class WalletLoginLocator {
  private WalletLoginLocator() {}

  public static String create(String handle, String idpOrigin, String realm) {
    URI origin = requireOrigin(idpOrigin);
    return create(handle, URI.create(origin.toASCIIString() + "/"), realm);
  }

  public static String create(String handle, URI publicBaseUri, String realm) {
    if (handle == null || !handle.matches("[A-Za-z0-9_-]{43}")) {
      throw new IllegalArgumentException("transaction handle rejected");
    }
    URI base = requirePublicBase(publicBaseUri);
    if (realm == null || realm.isBlank() || realm.length() > 255) {
      throw new IllegalArgumentException("realm name rejected");
    }
    String encodedRealm = java.net.URLEncoder.encode(realm, StandardCharsets.UTF_8).replace("+", "%20");
    String relative = "realms/" + encodedRealm + "/" + WalletLoginTransportResource.EXTENSION_ID
        + "/v1/transactions/" + handle;
    String baseText = base.toASCIIString();
    String basePath = base.getRawPath();
    if (basePath == null || basePath.isEmpty() || !basePath.endsWith("/")) baseText += "/";
    return URI.create(baseText).resolve(relative).toASCIIString();
  }

  private static URI requirePublicBase(URI uri) {
    Objects.requireNonNull(uri);
    String rawPath = uri.getRawPath() == null ? "" : uri.getRawPath();
    String normalizedPath = uri.normalize().getRawPath() == null ? "" : uri.normalize().getRawPath();
    if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
        || uri.getRawAuthority().contains("@") || uri.getRawQuery() != null || uri.getRawFragment() != null
        || !normalizedPath.equals(rawPath)
        || rawPath.toLowerCase(java.util.Locale.ROOT).contains("%2e")) {
      throw new IllegalArgumentException("Keycloak base URI must be a trusted HTTPS URL");
    }
    return uri;
  }

  private static URI requireOrigin(String value) {
    URI uri = URI.create(Objects.requireNonNull(value));
    if (!uri.isAbsolute() || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
        || uri.getRawAuthority().contains("@") || uri.getRawPath() != null && !uri.getRawPath().isEmpty()
        || uri.getRawQuery() != null || uri.getRawFragment() != null) {
      throw new IllegalArgumentException("IdP must be an exact HTTPS origin");
    }
    return uri;
  }
}
