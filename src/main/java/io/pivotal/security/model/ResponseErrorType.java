package io.pivotal.security.model;

public enum ResponseErrorType {
  BAD_REQUEST("The request could not be fulfilled because the request path or "
    + "body did not meet expectation. Please check the documentation for "
    + "required formatting and retry your request.");

  private String error;

  ResponseErrorType(String error) {
    this.error = error;
  }

  String getError() {
    return error;
  }
}
