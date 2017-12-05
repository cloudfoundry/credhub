package org.cloudfoundry.credhub.audit;

import org.cloudfoundry.credhub.request.PermissionOperation;

public class EventAuditRecordParameters {
  private AuditingOperationCode auditingOperationCode;
  private String credentialName;
  private PermissionOperation aceOperation;
  private String aceActor;

  public EventAuditRecordParameters() {
    this(AuditingOperationCode.UNKNOWN_OPERATION, null);
  }

  public EventAuditRecordParameters(AuditingOperationCode auditingOperationCode) {
    this(auditingOperationCode, null, null, null);
  }

  public EventAuditRecordParameters(AuditingOperationCode auditingOperationCode, String credentialName) {
    this(auditingOperationCode, credentialName, null, null);
  }

  public EventAuditRecordParameters(
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      PermissionOperation permissionOperation,
      String aceActor
  ) {
    this.auditingOperationCode = auditingOperationCode;
    this.credentialName = credentialName;
    this.aceActor = aceActor;
    this.aceOperation = permissionOperation;
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

  public PermissionOperation getAceOperation() {
    return aceOperation;
  }

  public void setAceOperation(PermissionOperation aceOperation) {
    this.aceOperation = aceOperation;
  }

  public String getAceActor() {
    return aceActor;
  }

  public void setAceActor(String aceActor) {
    this.aceActor = aceActor;
  }
}
