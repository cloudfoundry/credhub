package org.cloudfoundry.credhub.exceptions;

public class EntryNotFoundException extends RuntimeException {

  public EntryNotFoundException(final String messageCode) {
    super(messageCode);
  }
}
