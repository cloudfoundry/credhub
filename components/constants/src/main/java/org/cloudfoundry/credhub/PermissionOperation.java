package org.cloudfoundry.credhub;

import java.util.Arrays;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonValue;

public enum PermissionOperation {
  READ("read"),
  WRITE("write"),
  DELETE("delete"),
  READ_ACL("read_acl"),
  WRITE_ACL("write_acl");

  private final String operation;

  PermissionOperation(final String operation) {
    this.operation = operation;
  }

  public static String getCommaSeparatedPermissionOperations() {
    return Arrays.stream(PermissionOperation.values())
      .map(PermissionOperation::getOperation)
      .collect(Collectors.joining(", "));
  }

  @JsonValue
  public String getOperation() {
    return operation;
  }
}
