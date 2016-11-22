package io.pivotal.security.service;

import org.springframework.http.ResponseEntity;

import java.util.function.Supplier;

public interface AuditLogService {
  ResponseEntity<?> performWithAuditing(AuditRecordBuilder auditRecordBuilder, Supplier<ResponseEntity<?>> action) throws Exception;
}
