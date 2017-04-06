package io.pivotal.security.exceptions;

public class KeyNotFoundException extends RuntimeException {
  public KeyNotFoundException(String message) {
    super(message);
  }
}
