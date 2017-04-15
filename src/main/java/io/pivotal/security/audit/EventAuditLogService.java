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
      Function<EventAuditRecordBuilder, T> respondToRequestFunction
  ) {
    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    final EventAuditRecordBuilder eventAuditRecordBuilder = new EventAuditRecordBuilder(userContext.getAclUser());
    boolean success = false;
    try {
      T response = respondToRequestFunction.apply(eventAuditRecordBuilder);
      success = true;
      return response;
    } finally {
      writeAuditRecord(requestUuid, eventAuditRecordBuilder, success, transaction);
    }
  }

  private void writeAuditRecord(
      RequestUuid requestUuid,
      EventAuditRecordBuilder eventAuditRecordBuilder,
      boolean success,
      TransactionStatus transaction
  ) {
    try {
      if (!success) {
        transactionManager.rollback(transaction);
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      }

      EventAuditRecord eventAuditRecord = eventAuditRecordBuilder.build(requestUuid.getUuid(), success);
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
