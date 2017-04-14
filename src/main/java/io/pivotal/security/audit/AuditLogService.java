package io.pivotal.security.audit;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.EventAuditRecordDataService;
import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import io.pivotal.security.service.SecurityEventsLogService;
import io.pivotal.security.util.ExceptionThrowingFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

import static io.pivotal.security.audit.AuditInterceptor.REQUEST_UUID_ATTRIBUTE;

@Service
public class AuditLogService {

  private final RequestAuditRecordDataService requestAuditRecordDataService;
  private final EventAuditRecordDataService eventAuditRecordDataService;
  private final TransactionManagerDelegate transactionManager;
  private final SecurityEventsLogService securityEventsLogService;
  private final RequestAuditLogFactory requestAuditLogFactory;

  @Autowired
  AuditLogService(
      RequestAuditRecordDataService requestAuditRecordDataService,
      EventAuditRecordDataService eventAuditRecordDataService,
      TransactionManagerDelegate transactionManager,
      SecurityEventsLogService securityEventsLogService,
      RequestAuditLogFactory requestAuditLogFactory
  ) {
    this.requestAuditRecordDataService = requestAuditRecordDataService;
    this.eventAuditRecordDataService = eventAuditRecordDataService;
    this.transactionManager = transactionManager;
    this.securityEventsLogService = securityEventsLogService;
    this.requestAuditLogFactory = requestAuditLogFactory;
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
    } catch (Exception e) {
      throw e;
    } finally {
      writeAuditRecord(request, eventAuditRecordBuilder, responseEntity, transaction);
    }

    return responseEntity;
  }

  private void writeAuditRecord(
      HttpServletRequest request,
      EventAuditRecordBuilder eventAuditRecordBuilder,
      ResponseEntity<?> responseEntity,
      TransactionStatus transaction
  ) {
    try {
      boolean responseSucceeded = responseEntity.getStatusCode().is2xxSuccessful();

      EventAuditRecord eventAuditRecord = eventAuditRecordBuilder.build((UUID) request.getAttribute(REQUEST_UUID_ATTRIBUTE), responseSucceeded);
      eventAuditRecordDataService.save(eventAuditRecord);

      transactionManager.commit(transaction);
    } catch (Exception e) {
      throw new AuditSaveFailureException("error.audit_save_failure", e);
    } finally {
      if (!transaction.isCompleted()) {
        transactionManager.rollback(transaction);
      }
    }
  }
}
