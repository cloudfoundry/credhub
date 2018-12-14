package org.cloudfoundry.credhub.exceptions;

public class InvalidQueryParameterException extends RuntimeException {
  private final String queryParameter;

  public InvalidQueryParameterException(final String message, final String queryParameter) {
    super(message);
    this.queryParameter = queryParameter;
  }

  public String getInvalidQueryParameter() {
    return queryParameter;
  }
}
