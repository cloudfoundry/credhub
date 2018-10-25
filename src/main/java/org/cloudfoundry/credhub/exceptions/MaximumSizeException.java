package org.cloudfoundry.credhub.exceptions;

public class MaximumSizeException extends RuntimeException {
  public MaximumSizeException(String message) {
    super(message);
  }
}
