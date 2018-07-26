package org.cloudfoundry.credhub.exceptions;

public class PermissionInvalidPathAndActorException extends RuntimeException {
  public PermissionInvalidPathAndActorException(String messageCode) {
    super(messageCode);
  }
}
