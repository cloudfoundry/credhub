package org.cloudfoundry.credhub.exceptions;

public class MaximumSizeException extends RuntimeException {
  public MaximumSizeException(final String message) {
    super(message);
  }
}
