package io.pivotal.security.exceptions;

public class IncorrectKeyException extends RuntimeException {

  public IncorrectKeyException(Exception e) {
    super(e);
  }
}
