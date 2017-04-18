package io.pivotal.security.audit;

import io.pivotal.security.request.AccessControlOperation;

import static io.pivotal.security.audit.AuditingOperationCode.UNKNOWN_OPERATION;

public class EventAuditRecordParameters {
  private AuditingOperationCode auditingOperationCode;
  private String credentialName;
  private AccessControlOperation aceOperation;
  private String aceActor;

  public EventAuditRecordParameters() {
    this(UNKNOWN_OPERATION, null);
  }

  public EventAuditRecordParameters(AuditingOperationCode auditingOperationCode, String credentialName) {
    this.auditingOperationCode = auditingOperationCode;
    this.credentialName = credentialName;
  }

  public AuditingOperationCode getAuditingOperationCode() {
    return auditingOperationCode;
  }

  public void setAuditingOperationCode(AuditingOperationCode auditingOperationCode) {
    this.auditingOperationCode = auditingOperationCode;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  public AccessControlOperation getAceOperation() {
    return aceOperation;
  }

  public void setAceOperation(AccessControlOperation aceOperation) {
    this.aceOperation = aceOperation;
  }

  public String getAceActor() {
    return aceActor;
  }

  public void setAceActor(String aceActor) {
    this.aceActor = aceActor;
  }
}
