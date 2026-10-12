package org.decentwallet.keycloak.wallet;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;

/** Small inline SVG QR renderer for the wallet's opaque HTTPS locator. */
public final class WalletQrCode {
  private static final int MAX_PAYLOAD_CHARS = 8192;

  private WalletQrCode() {}

  private static String svg(BitMatrix matrix) {
    StringBuilder path = new StringBuilder();
    for (int y = 0; y < matrix.getHeight(); y++) {
      for (int x = 0; x < matrix.getWidth(); x++) {
        if (matrix.get(x, y)) path.append('M').append(x).append(',').append(y).append("h1v1h-1z");
      }
    }
    return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 "
        + matrix.getWidth() + " " + matrix.getHeight() + "\"><path fill=\"#000\" d=\""
        + path + "\"/></svg>";
  }

  public static String svgDataUri(String payload) {
    if (payload == null || payload.isBlank() || payload.length() > MAX_PAYLOAD_CHARS) {
      throw new IllegalArgumentException("wallet QR payload rejected");
    }
    try {
      Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
      hints.put(EncodeHintType.MARGIN, 2);
      hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
      BitMatrix matrix = new QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 256, 256, hints);
      return "data:image/svg+xml;base64," + Base64.getEncoder().encodeToString(svg(matrix).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new IllegalStateException("wallet QR rendering failed", e);
    }
  }
}
