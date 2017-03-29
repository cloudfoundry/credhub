package io.pivotal.security.data;

import io.pivotal.security.entity.AuthFailureAuditRecord;
import io.pivotal.security.repository.AuthFailureAuditRecordRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthFailureAuditRecordDataService {

  private final AuthFailureAuditRecordRepository authFailureAuditRecordRepository;

  @Autowired
  AuthFailureAuditRecordDataService(
      AuthFailureAuditRecordRepository authFailureAuditRecordRepository) {
    this.authFailureAuditRecordRepository = authFailureAuditRecordRepository;
  }

  public AuthFailureAuditRecord save(AuthFailureAuditRecord record) {
    return authFailureAuditRecordRepository.save(record);
  }
}
