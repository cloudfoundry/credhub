package io.pivotal.security.exceptions;

public class PermissionException extends RuntimeException {
  public PermissionException(String message) {
    super(message);
  }
}
