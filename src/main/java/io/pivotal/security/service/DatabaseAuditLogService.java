package io.pivotal.security.service;

import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.util.CurrentTimeProvider;
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
import java.util.Collections;
import java.util.Map;
import java.util.function.Supplier;

@Service
public class DatabaseAuditLogService implements AuditLogService {

  @Autowired
  CurrentTimeProvider currentTimeProvider;

  @Autowired
  ResourceServerTokenServices tokenServices;

  @Autowired
  OperationAuditRecordDataService operationAuditRecordDataService;

  @Autowired
  PlatformTransactionManager transactionManager;

  @Autowired
  MessageSource messageSource;

  @Autowired
  SecurityEventsLogService securityEventsLogService;

  private MessageSourceAccessor messageSourceAccessor;

  @PostConstruct
  public void init() {
    messageSourceAccessor = new MessageSourceAccessor(messageSource);
  }

  @Override
  public ResponseEntity<?> performWithAuditing(AuditRecordBuilder auditRecordBuilder, Supplier<ResponseEntity<?>> action) throws
      Exception {
    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());

    boolean auditSuccess = true;

    ResponseEntity<?> responseEntity = new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    RuntimeException thrown = null;
    try {
      responseEntity = action.get();
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

    OperationAuditRecord auditRecord = getOperationAuditRecord(auditRecordBuilder, responseEntity.getStatusCodeValue(), auditSuccess);

    try {
      operationAuditRecordDataService.save(auditRecord);
      transactionManager.commit(transaction);
      securityEventsLogService.log(auditRecord);
    } catch (Exception e) {
      if (!transaction.isCompleted()) transactionManager.rollback(transaction);
      final Map<String, String> error = Collections.singletonMap("error", messageSourceAccessor.getMessage("error.audit_save_failure"));
      return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    if (thrown != null) {
      throw thrown;
    }

    return responseEntity;
  }

  private OperationAuditRecord getOperationAuditRecord(AuditRecordBuilder auditRecordBuilder, int statusCode, boolean success) throws Exception {
    return auditRecordBuilder
        .computeAccessToken(tokenServices)
        .setRequestStatus(statusCode)
        .setIsSuccess(success)
        .build(currentTimeProvider.getInstant());
  }

  /*
   * The "iat" and "exp" claims are parsed by Jackson as integers. That means we have a
   * Year-2038 bug. In the hope that Jackson will someday be fixed, this function returns
   * a numeric value as long.
   */
  private long claimValueAsLong(Map<String, Object> additionalInformation, String claimName) {
    return ((Number) additionalInformation.get(claimName)).longValue();
  }
}
