package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonValue;

public enum AccessControlOperation {
  READ("read"),
  WRITE("write"),
  DELETE("delete"),
  READ_ACL("read_acl"),
  WRITE_ACL("write_acl");

  private final String operation;

  AccessControlOperation(String operation) {
    this.operation = operation;
  }

  @JsonValue
  public String getOperation() {
    return operation;
  }
}
