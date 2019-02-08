package org.cloudfoundry.credhub.exceptions;

public class InvalidPermissionException extends RuntimeException {
  public InvalidPermissionException(final String messageCode) {
    super(messageCode);
  }
}
