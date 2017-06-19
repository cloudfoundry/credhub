package io.pivotal.security.exceptions;

public class InvalidAclOperationException extends RuntimeException {

  public InvalidAclOperationException(String messageCode) {
    super(messageCode);
  }
}
