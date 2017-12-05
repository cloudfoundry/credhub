package org.cloudfoundry.credhub.exceptions;

public class AuditSaveFailureException extends RuntimeException {
  public AuditSaveFailureException(String message, Exception e) {
    super(message, e);
  }
}
