package io.pivotal.security.audit;

public class EventAuditRecordParameters {
  private AuditingOperationCode auditingOperationCode;
  private String credentialName;

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
}
