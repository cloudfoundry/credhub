package org.cloudfoundry.credhub.exceptions;

public class KeyNotFoundException extends RuntimeException {
  public KeyNotFoundException(final String message) {
    super(message);
  }
}
