package io.pivotal.security.helper;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import org.springframework.data.domain.Sort;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.data.domain.Sort.Direction.DESC;

public class AuditingHelper {
  public static void verifyAuditing(
      RequestAuditRecordRepository requestAuditRecordRepository,
      EventAuditRecordRepository eventAuditRecordRepository,
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      String path
  ) {
    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);
    assertThat(requestAuditRecord.getPath(), equalTo(path));

    EventAuditRecord eventAuditRecord = eventAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);
    assertThat(eventAuditRecord.getOperation(), equalTo(auditingOperationCode.toString()));
    assertThat(eventAuditRecord.getCredentialName(), equalTo(credentialName));
  }

  public static void verifyAuditing(
      RequestAuditRecordRepository requestAuditRecordRepository,
      EventAuditRecordRepository eventAuditRecordRepository,
      AuditingOperationCode auditingOperationCode,
      String credentialName
  ) {
    verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, auditingOperationCode, credentialName, "/api/v1/data");
  }
}
