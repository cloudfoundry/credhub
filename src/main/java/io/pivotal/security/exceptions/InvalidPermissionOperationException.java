package io.pivotal.security.exceptions;

public class InvalidPermissionOperationException extends RuntimeException {

  public InvalidPermissionOperationException(String messageCode) {
    super(messageCode);
  }
}
