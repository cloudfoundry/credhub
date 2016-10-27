package io.pivotal.security.repository;

import io.pivotal.security.entity.OperationAuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OperationAuditRecordRepository extends JpaRepository<OperationAuditRecord, Long> {
}
