package io.pivotal.security.data;

import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.repository.OperationAuditRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OperationAuditRecordDataService {

  private final OperationAuditRecordRepository operationAuditRecordRepository;

  @Autowired
  OperationAuditRecordDataService(OperationAuditRecordRepository operationAuditRecordRepository) {
    this.operationAuditRecordRepository = operationAuditRecordRepository;
  }

  public OperationAuditRecord save(OperationAuditRecord record) {
    return operationAuditRecordRepository.save(record);
  }
}
