package io.pivotal.security.repository;

import io.pivotal.security.entity.OperationAuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditRecordRepository extends JpaRepository<OperationAuditRecord, Long> {
  List<OperationAuditRecord> findAll();
}
