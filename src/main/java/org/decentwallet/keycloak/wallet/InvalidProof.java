package org.decentwallet.keycloak.wallet;

/** Invalid or non-canonical wallet proof input. Messages never include input values. */
public final class InvalidProof extends IllegalArgumentException {
  public InvalidProof(String message) { super(message); }
  public InvalidProof(String message, Throwable cause) { super(message, cause); }
}
