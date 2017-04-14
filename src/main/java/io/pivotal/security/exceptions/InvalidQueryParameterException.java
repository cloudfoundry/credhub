package io.pivotal.security.exceptions;

public class InvalidQueryParameterException extends RuntimeException {
  private final String queryParameter;

  public InvalidQueryParameterException(String message, String queryParameter) {
    super(message);
    this.queryParameter = queryParameter;
  }

  public String getMissingQueryParameter() {
    return queryParameter;
  }
}
