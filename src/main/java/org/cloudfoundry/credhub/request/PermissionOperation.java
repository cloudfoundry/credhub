package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonValue;

public enum PermissionOperation {
  READ("read"),
  WRITE("write"),
  DELETE("delete"),
  READ_ACL("read_acl"),
  WRITE_ACL("write_acl");

  private final String operation;

  PermissionOperation(String operation) {
    this.operation = operation;
  }

  @JsonValue
  public String getOperation() {
    return operation;
  }
}
