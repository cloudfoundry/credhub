package org.cloudfoundry.credhub.exceptions;

public class PermissionDoesNotExistException extends RuntimeException {
  public PermissionDoesNotExistException(String messageCode) {
    super(messageCode);
  }
}
