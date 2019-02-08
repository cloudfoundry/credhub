package org.cloudfoundry.credhub.exceptions;

public class IncorrectKeyException extends RuntimeException {

  public IncorrectKeyException(final Exception e) {
    super(e);
  }
}
