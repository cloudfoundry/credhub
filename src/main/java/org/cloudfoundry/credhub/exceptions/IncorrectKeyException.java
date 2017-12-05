package org.cloudfoundry.credhub.exceptions;

public class IncorrectKeyException extends RuntimeException {

  public IncorrectKeyException(Exception e) {
    super(e);
  }
}
