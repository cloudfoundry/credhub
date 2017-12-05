package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.AuthFailureAuditRecord;
import org.cloudfoundry.credhub.repository.AuthFailureAuditRecordRepository;
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
