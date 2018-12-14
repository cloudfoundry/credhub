package org.cloudfoundry.credhub.exceptions;

public class PermissionDoesNotExistException extends RuntimeException {
  public PermissionDoesNotExistException(final String messageCode) {
    super(messageCode);
  }
}
