package io.pivotal.security.service;

import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.ExceptionThrowingFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

@Service
public class AuditLogService {

  private final CurrentTimeProvider currentTimeProvider;
  private final ResourceServerTokenServices tokenServices;
  private final OperationAuditRecordDataService operationAuditRecordDataService;
  private final PlatformTransactionManager transactionManager;
  private final SecurityEventsLogService securityEventsLogService;

  @Autowired
  AuditLogService(
      CurrentTimeProvider currentTimeProvider,
      ResourceServerTokenServices tokenServices,
      OperationAuditRecordDataService operationAuditRecordDataService,
      PlatformTransactionManager transactionManager,
      SecurityEventsLogService securityEventsLogService
  ) {
    this.currentTimeProvider = currentTimeProvider;
    this.tokenServices = tokenServices;
    this.operationAuditRecordDataService = operationAuditRecordDataService;
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

      OperationAuditRecord auditRecord = saveAuditRecord(auditRecordBuilder, responseEntity);
      transactionManager.commit(transaction);
      securityEventsLogService.log(auditRecord);
    } catch (Exception e) {
      throw new AuditSaveFailureException("error.audit_save_failure");
    } finally {
      if (!transaction.isCompleted()) {
        transactionManager.rollback(transaction);
      }
    }
  }

  private OperationAuditRecord saveAuditRecord(
      AuditRecordBuilder auditRecordBuilder,
      ResponseEntity<?> responseEntity
  ) {
    OperationAuditRecord auditRecord = auditRecordBuilder
        .setRequestStatus(responseEntity.getStatusCodeValue())
        .build(currentTimeProvider.getInstant(), tokenServices);
    return operationAuditRecordDataService.save(auditRecord);
  }
}
