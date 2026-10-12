package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

final class WalletLoginTemplateTest {
  @Test
  void statusPollCarriesCsrfForPendingAndAcceptedReceipt() throws Exception {
    String template = Files.readString(Path.of("src/main/resources/theme-resources/templates/wallet-login.ftl"));
    assertTrue(template.contains("const statusUrl = \"${walletStatusUri?js_string}\";"));
    assertTrue(template.contains("<img id=\"wallet-qr\""));
    assertTrue(template.contains("src=\"${walletQrDataUri?html}\""));
    assertTrue(template.contains("<p id=\"wallet-locator\">${walletChallengeLocator?html}</p>"));
    assertTrue(template.contains("Do not share the QR URL."));
    assertFalse(template.contains("walletChallengeUri"));
    assertFalse(template.contains("fetch(challengeUrl"));
    assertFalse(template.contains("fetch(proofUrl"));
    assertTrue(template.contains("fetch(statusUrl, {"));
    assertTrue(template.contains("credentials: \"same-origin\""));
    assertTrue(template.contains("headers: {\"Accept\": \"application/json\", \"X-Decent-CSRF\": csrfToken}"));
    assertTrue(template.contains("Do not share the QR URL."));
    assertTrue(template.contains("window.location.assign(candidate.href)"));
    assertTrue(template.contains("let polling = false;"));
    assertFalse(template.contains("window.walletLoginClient"));
    assertFalse(template.contains("fetch(challengeUrl"));
    assertFalse(template.contains("fetch(proofUrl"));
    assertTrue(template.contains("fetch(statusUrl, {"));
    assertEquals(1, count(template, "fetch(statusUrl, {"));
  }

  private static int count(String text, String value) {
    int count = 0;
    int index = 0;
    while ((index = text.indexOf(value, index)) >= 0) {
      count++;
      index += value.length();
    }
    return count;
  }
}
