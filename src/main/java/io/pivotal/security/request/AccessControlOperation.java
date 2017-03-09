package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonValue;

public enum AccessControlOperation {
  READ("read"),
  WRITE("write");

  private final String operation;

  AccessControlOperation(String operation) {
    this.operation = operation;
  }

  @JsonValue
  public String getOperation() {
    return operation;
  }
}
