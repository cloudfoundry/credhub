package org.cloudfoundry.credhub.exceptions;

public class PermissionAlreadyExistsException extends RuntimeException {
  public PermissionAlreadyExistsException(final String messageCode) {
    super(messageCode);
  }
}
