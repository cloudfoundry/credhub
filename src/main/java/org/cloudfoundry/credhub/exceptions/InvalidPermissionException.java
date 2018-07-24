package org.cloudfoundry.credhub.exceptions;

public class InvalidPermissionException extends RuntimeException {
  public InvalidPermissionException(String messageCode) {
    super(messageCode);
  }
}
