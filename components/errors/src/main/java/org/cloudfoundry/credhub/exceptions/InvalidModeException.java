package org.cloudfoundry.credhub.exceptions;

public class InvalidModeException extends RuntimeException {
  public InvalidModeException(final String messageCode) {
    super(messageCode);
  }
}
