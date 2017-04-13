package io.pivotal.security.audit;

import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.RequestAuditRecord;

public class EventAuditRecordBuilder {
  private final String actor;
  private String credentialName;
  private AuditingOperationCode auditingOperationCode;

  public EventAuditRecordBuilder(String actor) {
    this.actor = actor;
  }

  public void setAuditingOperationCode(AuditingOperationCode auditingOperationCode) {
    this.auditingOperationCode = auditingOperationCode;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  public EventAuditRecord build(RequestAuditRecord requestAuditRecord, boolean success) {
    final String operation = auditingOperationCode != null ? auditingOperationCode.toString() : null;
    return new EventAuditRecord(
        operation,
        credentialName,
        actor,
        requestAuditRecord.getUuid(),
        success
    );
  }
}
