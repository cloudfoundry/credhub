package io.pivotal.security.audit;

import io.pivotal.security.entity.EventAuditRecord;

import java.util.UUID;

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

  public EventAuditRecord build(UUID requestUuid, boolean success) {
    final String operation = auditingOperationCode != null ? auditingOperationCode.toString() : null;
    return new EventAuditRecord(
        operation,
        credentialName,
        actor,
        requestUuid,
        success
    );
  }
}
