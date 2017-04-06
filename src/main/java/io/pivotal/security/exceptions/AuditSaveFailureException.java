package io.pivotal.security.exceptions;

public class AuditSaveFailureException extends RuntimeException {
  public AuditSaveFailureException(String message) {
    super(message);
  }
}
