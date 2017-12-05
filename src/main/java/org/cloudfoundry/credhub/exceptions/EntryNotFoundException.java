package org.cloudfoundry.credhub.exceptions;

public class EntryNotFoundException extends RuntimeException {

  public EntryNotFoundException(String messageCode) {
    super(messageCode);
  }
}
