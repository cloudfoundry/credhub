package io.pivotal.security.service;

import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.ExceptionThrowingFunction;
import io.pivotal.security.view.ResponseError;
import java.util.function.Supplier;
import javax.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import javax.annotation.PostConstruct;

@Service
public class DatabaseAuditLogService implements AuditLogService {

  private final CurrentTimeProvider currentTimeProvider;
  private final ResourceServerTokenServices tokenServices;
  private final OperationAuditRecordDataService operationAuditRecordDataService;
  private final PlatformTransactionManager transactionManager;
  private final MessageSource messageSource;
  private final SecurityEventsLogService securityEventsLogService;
  private MessageSourceAccessor messageSourceAccessor;

  @Autowired
  DatabaseAuditLogService(
      CurrentTimeProvider currentTimeProvider,
      ResourceServerTokenServices tokenServices,
      OperationAuditRecordDataService operationAuditRecordDataService,
      PlatformTransactionManager transactionManager,
      MessageSource messageSource,
      SecurityEventsLogService securityEventsLogService
  ) {
    this.currentTimeProvider = currentTimeProvider;
    this.tokenServices = tokenServices;
    this.operationAuditRecordDataService = operationAuditRecordDataService;
    this.transactionManager = transactionManager;
    this.messageSource = messageSource;
    this.securityEventsLogService = securityEventsLogService;
  }

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @Override
  public ResponseEntity<?> performWithAuditing(ExceptionThrowingFunction<AuditRecordBuilder, ResponseEntity<?>, Exception> action) throws
      Exception {
    AuditRecordBuilder auditRecordBuilder = new AuditRecordBuilder();
    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());

    boolean auditSuccess = true;

    ResponseEntity<?> responseEntity = new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    RuntimeException thrown = null;
    try {
      responseEntity = action.apply(auditRecordBuilder);
      if (!responseEntity.getStatusCode().is2xxSuccessful()) {
        auditSuccess = false;
        transactionManager.rollback(transaction);
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      }
    } catch (RuntimeException e) {
      thrown = e;
      auditSuccess = false;
      transactionManager.rollback(transaction);
      transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    }

    OperationAuditRecord auditRecord = getOperationAuditRecord(auditRecordBuilder,
        responseEntity.getStatusCodeValue(), auditSuccess);

    try {
      operationAuditRecordDataService.save(auditRecord);
      transactionManager.commit(transaction);
      securityEventsLogService.log(auditRecord);
    } catch (Exception e) {
      if (!transaction.isCompleted()) {
        transactionManager.rollback(transaction);
      }
      final ResponseError error = new ResponseError(
          messageSourceAccessor.getMessage("error.audit_save_failure"));
      return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    if (thrown != null) {
      throw thrown;
    }

    return responseEntity;
  }

  private OperationAuditRecord getOperationAuditRecord(AuditRecordBuilder auditRecordBuilder,
      int statusCode, boolean success) throws Exception {
    return auditRecordBuilder
        .setRequestStatus(statusCode)
        .setIsSuccess(success)
        .build(currentTimeProvider.getInstant(), tokenServices);
  }

}
