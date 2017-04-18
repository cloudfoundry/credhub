package io.pivotal.security.audit;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.EventAuditRecordDataService;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.function.Function;

import static io.pivotal.security.audit.AuditLogFactory.createEventAuditRecord;

@Service
public class EventAuditLogService {

  private final EventAuditRecordDataService eventAuditRecordDataService;
  private final TransactionManagerDelegate transactionManager;

  @Autowired
  EventAuditLogService(
      EventAuditRecordDataService eventAuditRecordDataService,
      TransactionManagerDelegate transactionManager
  ) {
    this.eventAuditRecordDataService = eventAuditRecordDataService;
    this.transactionManager = transactionManager;
  }

  public <T> T auditEvent(
      RequestUuid requestUuid,
      UserContext userContext,
      Function<EventAuditRecordParameters, T> respondToRequestFunction
  ) {
    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    final EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters();
    boolean success = false;
    try {
      T response = respondToRequestFunction.apply(eventAuditRecordParameters);
      success = true;
      return response;
    } finally {
      writeAuditRecord(requestUuid, userContext, eventAuditRecordParameters, success, transaction);
    }
  }

  private void writeAuditRecord(
      RequestUuid requestUuid,
      UserContext userContext,
      EventAuditRecordParameters eventAuditRecordParameters,
      boolean success,
      TransactionStatus transaction
  ) {
    try {
      if (!success) {
        transactionManager.rollback(transaction);
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      }

      final EventAuditRecord eventAuditRecord = createEventAuditRecord(
          eventAuditRecordParameters,
          userContext,
          requestUuid.getUuid(),
          success
      );
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
