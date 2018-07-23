package org.cloudfoundry.credhub.exceptions;

public class PermissionAlreadyExistsException extends RuntimeException {

  public PermissionAlreadyExistsException(String messageCode) {
    super(messageCode);
  }
}
