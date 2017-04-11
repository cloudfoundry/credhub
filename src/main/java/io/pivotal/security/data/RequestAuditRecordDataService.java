package io.pivotal.security.data;

import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class RequestAuditRecordDataService {

  private final RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  RequestAuditRecordDataService(RequestAuditRecordRepository requestAuditRecordRepository) {
    this.requestAuditRecordRepository = requestAuditRecordRepository;
  }

  public RequestAuditRecord save(RequestAuditRecord record) {
    return requestAuditRecordRepository.save(record);
  }
}
