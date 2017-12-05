package org.cloudfoundry.credhub.exceptions;

public class InvalidPermissionOperationException extends RuntimeException {

  public InvalidPermissionOperationException(String messageCode) {
    super(messageCode);
  }
}
