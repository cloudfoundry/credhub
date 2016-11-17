package io.pivotal.security.service;

import io.pivotal.security.entity.AuditingOperationCode;
import org.springframework.http.ResponseEntity;

import java.util.function.Supplier;

public interface AuditLogService {
  ResponseEntity<?> performWithAuditing(AuditingOperationCode operation, AuditRecordParameters auditRecordParameters, Supplier<ResponseEntity<?>> action) throws Exception;
}
