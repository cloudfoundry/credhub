package io.pivotal.security.audit;

public enum AuditingOperationCode {
  CREDENTIAL_ACCESS("credential_access"),
  CREDENTIAL_FIND("credential_find"),
  CREDENTIAL_DELETE("credential_delete"),
  CREDENTIAL_UPDATE("credential_update"),
  UNKNOWN_OPERATION("unknown_operation"),
  ACL_ACCESS("acl_access");

  private String operation;

  AuditingOperationCode(String operation) {
    this.operation = operation;
  }

  public String toString() {
    return operation;
  }
}
