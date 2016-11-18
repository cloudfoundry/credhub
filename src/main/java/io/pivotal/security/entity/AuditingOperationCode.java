package io.pivotal.security.entity;

public enum AuditingOperationCode {
  CREDENTIAL_ACCESS ("credential_access"),
  CREDENTIAL_FIND ("credential_find"),
  CREDENTIAL_DELETE ("credential_delete"),
  CREDENTIAL_UPDATE ("credential_update"),
  AUTHORITY_ACCESS ("ca_access"),
  AUTHORITY_UPDATE ("ca_update"),
  UNKNOWN_OPERATION ("unknown_operation");

  private String operation;

  AuditingOperationCode(String operation) { this.operation = operation; }

  public String toString() {
    return operation;
  }
}
