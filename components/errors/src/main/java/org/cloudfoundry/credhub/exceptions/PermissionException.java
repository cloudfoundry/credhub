package org.cloudfoundry.credhub.exceptions;

public class PermissionException extends RuntimeException {
  public PermissionException(final String message) {
    super(message);
  }
}
