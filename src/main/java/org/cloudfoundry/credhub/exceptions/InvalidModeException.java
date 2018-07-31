package org.cloudfoundry.credhub.exceptions;

public class InvalidModeException extends RuntimeException{
  public InvalidModeException(String messageCode) {
    super(messageCode);
  }
}
