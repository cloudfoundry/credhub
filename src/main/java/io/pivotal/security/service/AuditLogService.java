package io.pivotal.security.service;

import org.springframework.http.ResponseEntity;

import java.util.function.Supplier;

public interface AuditLogService {
  ResponseEntity<?> performWithAuditing(String operation, AuditRecordParameters auditRecordParameters, Supplier<ResponseEntity<?>> action);
}
