package org.cloudfoundry.credhub.repository;

import org.cloudfoundry.credhub.entity.EventAuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EventAuditRecordRepository extends JpaRepository<EventAuditRecord, Long> {

}
