package io.pivotal.security.model;

public class ResponseError {
  public String error;

  public ResponseError(ResponseErrorType type) {
    this.error = type.getError();
  }

  public String getError() {
    return error;
  }
}
