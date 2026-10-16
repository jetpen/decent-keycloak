package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

final class WalletQrCodeTest {
  @Test
  void rendersOpaqueWalletChallengeUriAsInlineSvgQrCode() {
    String locator = "https://idp.example/realms/demo/decent-wallet-login/"
        + "A".repeat(43) + "/challenge";

    String dataUri = WalletQrCode.svgDataUri(locator);

    assertTrue(dataUri.startsWith("data:image/svg+xml;base64,"));
    String svg = new String(Base64.getDecoder().decode(dataUri.substring(dataUri.indexOf(',') + 1)),
        StandardCharsets.UTF_8);
    assertTrue(svg.startsWith("<svg "));
    assertTrue(svg.contains("<path"));
    assertFalse(svg.contains(locator));
  }

  @Test
  void locatorIsAnHttpsTransactionUrlAndContainsNoProofMaterial() {
    String handle = "A".repeat(43);

    String locator = WalletLoginLocator.create(handle, "https://idp.example", "demo");

    assertEquals("https://idp.example/realms/demo/decent-wallet-login/v1/transactions/" + handle, locator);
    assertFalse(locator.startsWith("decent-wallet-login://"));
    assertFalse(locator.contains("challenge="));
    assertFalse(locator.contains("signature="));
  }

  @Test
  void locatorPreservesTrustedKeycloakPathPrefix() {
    String locator = WalletLoginLocator.create("A".repeat(43),
        java.net.URI.create("https://idp.example/auth"), "demo");

    assertEquals("https://idp.example/auth/realms/demo/decent-wallet-login/v1/transactions/"
        + "A".repeat(43), locator);
  }

  @Test
  void locatorRejectsPathTraversalInPublicBase() {
    assertThrows(IllegalArgumentException.class, () -> WalletLoginLocator.create("A".repeat(43),
        java.net.URI.create("https://idp.example/auth/../evil/"), "demo"));
    assertThrows(IllegalArgumentException.class, () -> WalletLoginLocator.create("A".repeat(43),
        java.net.URI.create("https://idp.example/%2e%2e/"), "demo"));
  }

  @Test
  void locatorRequiresAnExactHttpsIdpOrigin() {
    assertThrows(IllegalArgumentException.class,
        () -> WalletLoginLocator.create("A".repeat(43), "http://idp.example", "demo"));
    assertThrows(IllegalArgumentException.class,
        () -> WalletLoginLocator.create("A".repeat(43), "https://idp.example/path", "demo"));
  }

  @Test
  void locatorRejectsUntrustedOriginSyntax() {
    assertThrows(IllegalArgumentException.class,
        () -> WalletLoginLocator.create("A".repeat(43), "http://idp.example", "demo"));
    assertThrows(IllegalArgumentException.class,
        () -> WalletLoginLocator.create("A".repeat(43), "https://idp.example/path", "demo"));
    assertThrows(IllegalArgumentException.class,
        () -> WalletLoginLocator.create("A".repeat(43), "https://user@idp.example", "demo"));
  }

  @Test
  void locatorEscapesRealmPathSegment() {
    String locator = WalletLoginLocator.create("A".repeat(43), "https://idp.example", "demo realm");
    assertTrue(locator.startsWith("https://idp.example/realms/demo%20realm/"));
  }

  @Test
  void rejectsBlankOrOversizedPayloads() {
    assertThrows(IllegalArgumentException.class, () -> WalletQrCode.svgDataUri(""));
    assertThrows(IllegalArgumentException.class, () -> WalletQrCode.svgDataUri("x".repeat(8193)));
  }
}
