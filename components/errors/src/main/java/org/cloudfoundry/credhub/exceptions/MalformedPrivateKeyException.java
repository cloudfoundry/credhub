package org.cloudfoundry.credhub.exceptions;

public class MalformedPrivateKeyException extends RuntimeException {
  public MalformedPrivateKeyException(final String messageCode) {
    super(messageCode);
  }

  public MalformedPrivateKeyException() {
    super();
  }
}
