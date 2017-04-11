package io.pivotal.security.audit;

import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import io.pivotal.security.service.SecurityEventsLogService;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.ExceptionThrowingFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.Collection;

@Service
public class AuditLogService {

  private final CurrentTimeProvider currentTimeProvider;
  private final RequestAuditRecordDataService requestAuditRecordDataService;
  private final PlatformTransactionManager transactionManager;
  private final SecurityEventsLogService securityEventsLogService;

  @Autowired
  AuditLogService(
      CurrentTimeProvider currentTimeProvider,
      RequestAuditRecordDataService requestAuditRecordDataService,
      PlatformTransactionManager transactionManager,
      SecurityEventsLogService securityEventsLogService
  ) {
    this.currentTimeProvider = currentTimeProvider;
    this.requestAuditRecordDataService = requestAuditRecordDataService;
    this.transactionManager = transactionManager;
    this.securityEventsLogService = securityEventsLogService;
  }

  public ResponseEntity<?> performWithAuditing(
      ExceptionThrowingFunction<AuditRecordBuilder, ResponseEntity<?>, Exception> respondToRequestFunction
  ) throws Exception {
    AuditRecordBuilder auditRecordBuilder = new AuditRecordBuilder();
    ResponseEntity<?> responseEntity = new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    try {
      responseEntity = respondToRequestFunction.apply(auditRecordBuilder);
    } finally {
      writeAuditRecord(auditRecordBuilder, responseEntity, transaction);
    }

    return responseEntity;
  }

  private void writeAuditRecord(
      AuditRecordBuilder auditRecordBuilder,
      ResponseEntity<?> responseEntity,
      TransactionStatus transaction
  ) {
    try {
      boolean responseSucceeded = responseEntity.getStatusCode().is2xxSuccessful();

      if (!responseSucceeded) {
        transactionManager.rollback(transaction);
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      }
      auditRecordBuilder.setIsSuccess(responseSucceeded);

      Collection<RequestAuditRecord> auditRecords = saveAuditRecord(auditRecordBuilder, responseEntity);

      transactionManager.commit(transaction);

      auditRecords.forEach(securityEventsLogService::log);
    } catch (Exception e) {
      throw new AuditSaveFailureException("error.audit_save_failure");
    } finally {
      if (!transaction.isCompleted()) {
        transactionManager.rollback(transaction);
      }
    }
  }

  private Collection<RequestAuditRecord> saveAuditRecord(
      AuditRecordBuilder auditRecordBuilder,
      ResponseEntity<?> responseEntity
  ) {
    Collection<RequestAuditRecord> auditRecords = auditRecordBuilder
        .setRequestStatus(responseEntity.getStatusCodeValue())
        .build(currentTimeProvider.getInstant());

    auditRecords.forEach(requestAuditRecordDataService::save);

    return auditRecords;
  }
}
