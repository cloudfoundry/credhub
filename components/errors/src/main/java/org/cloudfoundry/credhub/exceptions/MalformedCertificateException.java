package org.cloudfoundry.credhub.exceptions;

public class MalformedCertificateException extends RuntimeException {
  public MalformedCertificateException(final String message) {
    super(message);
  }

  public MalformedCertificateException() {
    super();
  }
}
