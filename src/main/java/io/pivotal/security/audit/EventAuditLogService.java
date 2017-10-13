package io.pivotal.security.audit;

import io.pivotal.security.auth.UserContextHolder;
import io.pivotal.security.data.EventAuditRecordDataService;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import java.util.List;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditLogFactory.createEventAuditRecord;

@Service
public class EventAuditLogService {

  private final EventAuditRecordDataService eventAuditRecordDataService;
  private final TransactionManagerDelegate transactionManager;
  private final UserContextHolder userContextHolder;

  @Autowired
  EventAuditLogService(
      EventAuditRecordDataService eventAuditRecordDataService,
      TransactionManagerDelegate transactionManager,
      UserContextHolder userContextHolder) {
    this.eventAuditRecordDataService = eventAuditRecordDataService;
    this.transactionManager = transactionManager;
    this.userContextHolder = userContextHolder;
  }

  public <T> T auditEvents(
      RequestUuid requestUuid,
      Function<List<EventAuditRecordParameters>, T> respondToRequestFunction
  ) {
    TransactionStatus transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
    final List<EventAuditRecordParameters> eventAuditRecordParametersList = newArrayList();
    boolean success = false;
    try {
      T response = respondToRequestFunction.apply(eventAuditRecordParametersList);
      success = true;
      return response;
    } finally {
      writeAuditRecords(requestUuid, eventAuditRecordParametersList, success, transaction);
    }
  }

  private void writeAuditRecords(
      RequestUuid requestUuid,
      List<EventAuditRecordParameters> eventAuditRecordParametersList,
      boolean success,
      TransactionStatus transaction
  ) {
    try {
      if (!success) {
        transactionManager.rollback(transaction);
        transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
      }

      final UUID uuid = requestUuid.getUuid();
      final List<EventAuditRecord> eventAuditRecords = eventAuditRecordParametersList
          .stream()
          .map(parameters -> createEventAuditRecord(parameters, userContextHolder.getUserContext(), uuid, success))
          .collect(Collectors.toList());
      eventAuditRecordDataService.save(eventAuditRecords);

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
