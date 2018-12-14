package org.cloudfoundry.credhub.exceptions;

public class InvalidPermissionOperationException extends RuntimeException {
  public InvalidPermissionOperationException(final String messageCode) {
    super(messageCode);
  }
}
