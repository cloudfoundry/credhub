package io.pivotal.security.exceptions;

public class EntryNotFoundException extends RuntimeException {
  public EntryNotFoundException(String messageCode) {
    super(messageCode);
  }
}
