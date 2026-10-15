package org.decentwallet.keycloak.wallet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

final class WalletLoginTemplateTest {
  @Test
  void rendersUnderKeycloakHtmlAutoescapingWithoutCorruptingScriptUrls() throws Exception {
    var config = new freemarker.template.Configuration(freemarker.template.Configuration.VERSION_2_3_35);
    config.setOutputFormat(freemarker.core.HTMLOutputFormat.INSTANCE);
    config.setAutoEscapingPolicy(freemarker.template.Configuration.ENABLE_IF_SUPPORTED_AUTO_ESCAPING_POLICY);
    var loader = new freemarker.cache.StringTemplateLoader();
    loader.putTemplate("template.ftl", "<#macro registrationLayout displayMessage><#nested 'form'></#macro>");
    loader.putTemplate("wallet-login.ftl", Files.readString(Path.of("src/main/resources/theme-resources/templates/wallet-login.ftl")));
    config.setTemplateLoader(loader);
    String url = "https://idp.example/auth/status?client_id=client&tab_id=tab";
    var templateModel = new java.util.HashMap<String, Object>();
    templateModel.put("walletSiteLabel", "<script>alert(1)</script>");
    templateModel.put("walletOriginLabel", "https://idp.example");
    templateModel.put("walletExpiresAt", "later");
    templateModel.put("walletQrDataUri", "data:image/svg+xml;base64,abc");
    templateModel.put("walletChallengeLocator", "https://idp.example/transaction");
    templateModel.put("walletStatusUri", url);
    templateModel.put("walletCsrfToken", "C".repeat(43));
    templateModel.put("walletIntent", "login");
    templateModel.put("url", java.util.Map.of("loginAction", "/auth/action"));
    var writer = new java.io.StringWriter();
    config.getTemplate("wallet-login.ftl").process(templateModel, writer);
    String rendered = writer.toString();
    assertTrue(rendered.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assertFalse(rendered.contains("<script>alert(1)</script>"));
    assertTrue(rendered.contains("name=\"wallet_intent\" value=\"signup\""));
    assertTrue(rendered.contains("const statusUrl = \"" + url + "\";"));
    var hostile = new java.io.StringWriter();
    templateModel.put("walletStatusUri", "https://idp.example/status?x=\"</script><script>alert(1)</script>");
    config.getTemplate("wallet-login.ftl").process(templateModel, hostile);
    assertFalse(hostile.toString().contains("</script><script>alert(1)</script>"));
  }

  @Test
  void configuredSiteNameIsEscapedAndDisplayedSeparatelyFromTheWalletOrigin() throws Exception {
    String template = Files.readString(Path.of("src/main/resources/theme-resources/templates/wallet-login.ftl"));
    assertTrue(template.contains("<p id=\"wallet-site-name\">${walletSiteLabel}</p>"));
    assertTrue(template.contains("<p id=\"wallet-origin\">${walletOriginLabel}</p>"));
  }

  @Test
  void statusPollCarriesCsrfForPendingAndAcceptedReceipt() throws Exception {
    String template = Files.readString(Path.of("src/main/resources/theme-resources/templates/wallet-login.ftl"));
    assertTrue(template.contains("const statusUrl = \"${walletStatusUri?js_string?no_esc}\";"));
    assertTrue(template.contains("<img id=\"wallet-qr\""));
    assertTrue(template.contains("src=\"${walletQrDataUri}\""));
    assertTrue(template.contains("<p id=\"wallet-locator\">${walletChallengeLocator}</p>"));
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

  @Test
  void startsStatusPollingForBothLoginAndSignupIntents() throws Exception {
    String template = Files.readString(Path.of("src/main/resources/theme-resources/templates/wallet-login.ftl"));
    assertTrue(template.contains("if (walletIntent === \"login\" || walletIntent === \"signup\") {"));
    assertTrue(template.contains("window.setTimeout(poll, 1500);"));
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
