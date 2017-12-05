package org.cloudfoundry.credhub.exceptions;

public class KeyNotFoundException extends RuntimeException {
  public KeyNotFoundException(String message) {
    super(message);
  }
}
