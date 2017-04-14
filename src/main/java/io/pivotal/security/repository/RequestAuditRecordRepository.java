package io.pivotal.security.repository;

import io.pivotal.security.entity.RequestAuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RequestAuditRecordRepository extends JpaRepository<RequestAuditRecord, Long> {
}
