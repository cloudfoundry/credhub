package org.cloudfoundry.credhub.repository;

import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RequestAuditRecordRepository extends JpaRepository<RequestAuditRecord, Long> {
}
