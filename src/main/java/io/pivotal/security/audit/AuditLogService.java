package io.pivotal.security.audit;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.EventAuditRecordDataService;
import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import io.pivotal.security.service.SecurityEventsLogService;
import io.pivotal.security.util.ExceptionThrowingFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import static io.pivotal.security.audit.RequestAuditLogFactory.createRequestAuditRecord;

import javax.servlet.http.HttpServletRequest;

@Service
public class AuditLogService {

  private final RequestAuditRecordDataService requestAuditRecordDataService;
  private final EventAuditRecordDataService eventAuditRecordDataService;
  private final TransactionManagerDelegate transactionManager;
  private final SecurityEventsLogService securityEventsLogService;

  @Autowired
  AuditLogService(
      RequestAuditRecordDataService requestAuditRecordDataService,
      EventAuditRecordDataService eventAuditRecordDataService,
      TransactionManagerDelegate transactionManager,
      SecurityEventsLogService securityEventsLogService
  ) {
    this.requestAuditRecordDataService = requestAuditRecordDataService;
    this.eventAuditRecordDataService = eventAuditRecordDataService;
    this.transactionManager = transactionManager;
    this.securityEventsLogService = securityEventsLogService;
  }

  public ResponseEntity<?> performWithAuditing(
      HttpServletRequest request,
      UserContext userContext,
      ExceptionThrowingFunction<EventAuditRecordBuilder, ResponseEntity<?>, Exception> respondToRequestFunction
  ) throws Exception {
    ResponseEntity<?> responseEntity = new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);

    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    final EventAuditRecordBuilder eventAuditRecordBuilder = new EventAuditRecordBuilder(userContext.getAclUser());
    try {
      responseEntity = respondToRequestFunction.apply(eventAuditRecordBuilder);
    } finally {
      writeAuditRecord(request, userContext, eventAuditRecordBuilder, responseEntity, transaction);
    }

    return responseEntity;
  }

  private void writeAuditRecord(
      HttpServletRequest request,
      UserContext userContext,
      EventAuditRecordBuilder eventAuditRecordBuilder,
      ResponseEntity<?> responseEntity,
      TransactionStatus transaction
  ) {
    try {
      boolean responseSucceeded = responseEntity.getStatusCode().is2xxSuccessful();

      if (!responseSucceeded) {
        transactionManager.rollback(transaction);
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      }

      RequestAuditRecord requestAuditRecord = createRequestAuditRecord(request, userContext, responseEntity.getStatusCodeValue());
      requestAuditRecord = requestAuditRecordDataService.save(requestAuditRecord);

      EventAuditRecord eventAuditRecord = eventAuditRecordBuilder.build(requestAuditRecord, responseSucceeded);
      eventAuditRecordDataService.save(eventAuditRecord);

      transactionManager.commit(transaction);

      securityEventsLogService.log(requestAuditRecord);
    } catch (Exception e) {
      throw new AuditSaveFailureException("error.audit_save_failure", e);
    } finally {
      if (!transaction.isCompleted()) {
        transactionManager.rollback(transaction);
      }
    }
  }
}
