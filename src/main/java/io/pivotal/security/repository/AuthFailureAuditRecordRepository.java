package io.pivotal.security.repository;

import io.pivotal.security.entity.AuthFailureAuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthFailureAuditRecordRepository extends JpaRepository<AuthFailureAuditRecord, Long> {
}
