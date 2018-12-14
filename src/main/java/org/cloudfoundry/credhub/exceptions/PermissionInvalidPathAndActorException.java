package org.cloudfoundry.credhub.exceptions;

public class PermissionInvalidPathAndActorException extends RuntimeException {
  public PermissionInvalidPathAndActorException(final String messageCode) {
    super(messageCode);
  }
}
