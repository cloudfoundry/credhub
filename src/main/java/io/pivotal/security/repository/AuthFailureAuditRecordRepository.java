package io.pivotal.security.repository;

import io.pivotal.security.entity.AuthFailureAuditRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuthFailureAuditRecordRepository extends JpaRepository<AuthFailureAuditRecord, Long> {
  List<AuthFailureAuditRecord> findAll();
  AuthFailureAuditRecord findFirstByOrderByIdDesc();
}
