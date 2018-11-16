package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Arrays;
import java.util.stream.Collectors;

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

  public static String getCommaSeparatedPermissionOperations() {
    return Arrays.stream(PermissionOperation.values())
      .map(PermissionOperation::getOperation)
      .collect(Collectors.joining(", "));
  }
}
